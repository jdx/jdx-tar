use super::format::path_requires_directory;
use super::{EntryType, Header, MAX_METADATA_SIZE, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

const BLOCK_LEN: usize = 512;
const NAME_LEN: usize = 100;
const LINK_LEN: usize = 100;

/// A synchronous, streaming tar archive writer.
///
/// The writer emits deterministic GNU-format headers: unused fields are
/// zeroed and checksums are always recalculated by the builder.
pub struct Builder<W: Write> {
    inner: W,
    finished: bool,
    poisoned: bool,
}

impl<W: Write> Builder<W> {
    /// Creates an archive writer around `inner`.
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            finished: false,
            poisoned: false,
        }
    }

    /// Appends a logical entry at `path`.
    ///
    /// Exactly `header.stored_size()` bytes are read from `data`. Paths longer
    /// than the GNU header field are emitted using a GNU long-name record. Raw
    /// extension and sparse headers are not accepted through this entry API.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or header cannot be represented, the
    /// entry type or payload shape is unsupported, the input is shorter than its
    /// declared size, or writing fails. The caller header changes only on success.
    pub fn append_data<P: AsRef<Path>, R: Read>(
        &mut self,
        header: &mut Header,
        path: P,
        data: R,
    ) -> Result<()> {
        self.ensure_writable()?;
        if matches!(header.type_flag, b'x' | b'g' | b'L' | b'K' | b'S') {
            return Err(invalid(
                "raw extension and sparse headers are not logical writer entries",
            ));
        }
        if matches!(header.type_flag, b'1'..=b'6') && header.stored_size != 0 {
            return Err(invalid("nonregular entries cannot carry payload"));
        }
        let link_target = if matches!(header.type_flag, b'1' | b'2') {
            let target = header
                .link_name
                .as_deref()
                .ok_or_else(|| invalid("tar link target is missing"))?;
            validate_name(target, "tar link target is empty or contains NUL")?;
            if target.len() > LINK_LEN {
                long_record_size(target)?;
            }
            if header.type_flag == b'1' {
                validate_directory_suffix(target, false)?;
            }
            Some(target)
        } else {
            None
        };
        let path = path_bytes(path.as_ref());
        validate_name(&path, "tar entry path is empty or contains NUL")?;
        validate_directory_suffix(&path, header.type_flag == b'5')?;
        if path.len() > NAME_LEN {
            long_record_size(&path)?;
        }
        let mut resolved = header.clone();
        resolved.path.clone_from(&path);
        encode_header(&resolved)?;
        if let Some(target) = link_target.filter(|target| target.len() > LINK_LEN) {
            self.append_long_record(b'K', target)?;
        }
        if path.len() > NAME_LEN {
            self.append_long_record(b'L', &path)?;
        }
        self.append_resolved(&resolved, data)?;
        *header = resolved;
        Ok(())
    }

    /// Appends a symbolic or hard link.
    ///
    /// Link targets longer than the GNU header field are emitted using a GNU
    /// long-link record.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-link header, an empty target, an
    /// unrepresentable header, or a write failure.
    pub fn append_link<P: AsRef<Path>, T: AsRef<Path>>(
        &mut self,
        header: &mut Header,
        path: P,
        target: T,
    ) -> Result<()> {
        self.ensure_writable()?;
        if !matches!(
            EntryType::from_flag(header.type_flag),
            EntryType::Symlink | EntryType::Hardlink
        ) {
            return Err(invalid("append_link requires a symlink or hardlink header"));
        }
        let path = path_bytes(path.as_ref());
        validate_name(&path, "tar entry path is empty or contains NUL")?;
        validate_directory_suffix(&path, false)?;
        let target = path_bytes(target.as_ref());
        validate_name(&target, "tar link target is empty or contains NUL")?;
        if header.type_flag == b'1' {
            validate_directory_suffix(&target, false)?;
        }
        let mut resolved = header.clone();
        resolved.link_name = Some(target);
        resolved.stored_size = 0;
        resolved.path.clone_from(&path);
        if let Some(target) = resolved
            .link_name
            .as_deref()
            .filter(|target| target.len() > LINK_LEN)
        {
            long_record_size(target)?;
        }
        if path.len() > NAME_LEN {
            long_record_size(&path)?;
        }
        encode_header(&resolved)?;
        if let Some(target) = resolved
            .link_name
            .as_deref()
            .filter(|target| target.len() > LINK_LEN)
        {
            self.append_long_record(b'K', target)?;
        }
        if path.len() > NAME_LEN {
            self.append_long_record(b'L', &path)?;
        }
        self.append_resolved(&resolved, io::empty())?;
        *header = resolved;
        Ok(())
    }

    /// Writes the two zero blocks that terminate a tar archive.
    ///
    /// # Errors
    ///
    /// Returns an error when writing or flushing the wrapped writer fails.
    pub fn finish(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(invalid("cannot finish a poisoned tar archive"));
        }
        if !self.finished {
            if let Err(error) = self
                .inner
                .write_all(&[0_u8; BLOCK_LEN * 2])
                .and_then(|()| self.inner.flush())
            {
                self.poisoned = true;
                return Err(error);
            }
            self.finished = true;
        }
        Ok(())
    }

    /// Finishes the archive and returns the wrapped writer.
    ///
    /// # Errors
    ///
    /// Returns an error when finishing the archive fails.
    pub fn into_inner(mut self) -> Result<W> {
        self.finish()?;
        Ok(self.inner)
    }

    fn append_long_record(&mut self, flag: u8, value: &[u8]) -> Result<()> {
        let size = long_record_size(value)?;
        let mut header = Header::new_gnu(EntryType::Other(flag));
        header.path = b"././@LongLink".to_vec();
        header.mode = 0o644;
        header.stored_size = size;
        let mut data = value.to_vec();
        data.push(0);
        self.append_resolved(&header, data.as_slice())
    }

    fn ensure_writable(&self) -> Result<()> {
        if self.poisoned {
            return Err(invalid("cannot append to a poisoned tar archive"));
        }
        if self.finished {
            return Err(invalid("cannot append to a finished tar archive"));
        }
        Ok(())
    }

    fn append_resolved<R: Read>(&mut self, header: &Header, mut data: R) -> Result<()> {
        self.ensure_writable()?;
        let block = encode_header(header)?;
        let result = (|| {
            self.inner.write_all(&block)?;
            let copied = io::copy(&mut data.by_ref().take(header.stored_size), &mut self.inner)?;
            if copied != header.stored_size {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "tar entry data is shorter than its header size",
                ));
            }
            let padding = (512 - header.stored_size % 512) % 512;
            if padding != 0 {
                self.inner
                    .write_all(&[0_u8; BLOCK_LEN][..padding as usize])?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

fn validate_directory_suffix(path: &[u8], is_directory: bool) -> Result<()> {
    if !is_directory && path_requires_directory(path) {
        return Err(invalid(
            "only directory entries may have a directory-required path suffix",
        ));
    }
    Ok(())
}

fn validate_name(value: &[u8], message: &'static str) -> Result<()> {
    if value.is_empty() || value.contains(&0) {
        return Err(invalid(message));
    }
    Ok(())
}

fn long_record_size(value: &[u8]) -> Result<u64> {
    let size = value
        .len()
        .checked_add(1)
        .and_then(|size| u64::try_from(size).ok())
        .ok_or_else(|| invalid("GNU long-name record is too large"))?;
    if size > MAX_METADATA_SIZE {
        return Err(invalid("GNU long-name record exceeds 1 MiB limit"));
    }
    Ok(size)
}

fn encode_header(header: &Header) -> Result<[u8; BLOCK_LEN]> {
    let mut block = [0_u8; BLOCK_LEN];
    write_bytes(&mut block[..NAME_LEN], &header.path);
    write_numeric(&mut block[100..108], u64::from(header.mode), "mode")?;
    write_numeric(&mut block[108..116], header.uid, "uid")?;
    write_numeric(&mut block[116..124], header.gid, "gid")?;
    write_numeric(&mut block[124..136], header.stored_size, "size")?;
    write_signed_numeric(&mut block[136..148], header.mtime, "mtime")?;
    block[148..156].fill(b' ');
    block[156] = header.type_flag;
    if let Some(target) = &header.link_name {
        write_bytes(&mut block[157..257], target);
    }
    block[257..265].copy_from_slice(b"ustar  \0");
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    write_checksum(&mut block[148..156], checksum)?;
    Ok(block)
}

fn write_bytes(field: &mut [u8], value: &[u8]) {
    let len = value.len().min(field.len());
    field[..len].copy_from_slice(&value[..len]);
}

fn write_numeric(field: &mut [u8], value: u64, name: &'static str) -> Result<()> {
    let digits = field.len() - 1;
    let octal = format!("{value:0digits$o}");
    if octal.len() <= digits {
        field[..digits].copy_from_slice(octal.as_bytes());
        field[digits] = 0;
        return Ok(());
    }

    if field.len() < 9 && value >= (1_u64 << ((field.len() - 1) * 8)) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("tar {name} does not fit in its header field"),
        ));
    }
    field.fill(0);
    let encoded = value.to_be_bytes();
    let start = field.len().saturating_sub(encoded.len());
    let source = encoded.len().saturating_sub(field.len());
    field[start..].copy_from_slice(&encoded[source..]);
    field[0] |= 0x80;
    Ok(())
}

fn write_signed_numeric(field: &mut [u8], value: i64, name: &'static str) -> Result<()> {
    if value >= 0 {
        return write_numeric(field, value.unsigned_abs(), name);
    }
    field.fill(0xff);
    let encoded = value.to_be_bytes();
    let start = field.len().saturating_sub(encoded.len());
    let source = encoded.len().saturating_sub(field.len());
    field[start..].copy_from_slice(&encoded[source..]);
    field[0] |= 0x80;
    Ok(())
}

fn write_checksum(field: &mut [u8], checksum: u64) -> Result<()> {
    let value = format!("{checksum:06o}\0 ");
    if value.len() != field.len() {
        return Err(invalid("tar checksum does not fit in its header field"));
    }
    field.copy_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().replace('\\', "/").into_bytes()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}
