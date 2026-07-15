//! A secure, synchronous, streaming tar reader and extractor.
//!
//! This crate reads already-decompressed tar streams and supports all GNU
//! sparse formats commonly found in release archives.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

const BLOCK: u64 = 512;
const MAX_PAX_SIZE: u64 = 1024 * 1024;
const MAX_SPARSE_SEGMENTS: usize = 1_000_000;

/// The crate's result type.
pub type Result<T> = io::Result<T>;

/// One contiguous data region in a sparse file. Gaps are logical holes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseSegment {
    /// Logical byte offset at which data begins.
    pub offset: u64,
    /// Number of data bytes stored at this offset.
    pub len: u64,
}

/// The kind of an archive entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EntryType {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A hard link.
    Hardlink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A FIFO.
    Fifo,
    /// An unrecognized type flag.
    Other(u8),
}

impl EntryType {
    fn from_flag(flag: u8) -> Self {
        match flag {
            0 | b'0' | b'7' | b'S' => Self::File,
            b'5' => Self::Directory,
            b'2' => Self::Symlink,
            b'1' => Self::Hardlink,
            b'3' => Self::CharDevice,
            b'4' => Self::BlockDevice,
            b'6' => Self::Fifo,
            other => Self::Other(other),
        }
    }
}

/// Parsed metadata for a tar header.
#[derive(Clone, Debug)]
pub struct Header {
    path: Vec<u8>,
    link_name: Option<Vec<u8>>,
    mode: u32,
    uid: u64,
    gid: u64,
    stored_size: u64,
    mtime: i64,
    type_flag: u8,
}

impl Header {
    /// File mode from the header.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
    /// User id from the header.
    #[must_use]
    pub const fn uid(&self) -> u64 {
        self.uid
    }
    /// Group id from the header.
    #[must_use]
    pub const fn gid(&self) -> u64 {
        self.gid
    }
    /// Raw stored size before sparse expansion.
    #[must_use]
    pub const fn stored_size(&self) -> u64 {
        self.stored_size
    }
    /// Modification time as seconds since the Unix epoch.
    #[must_use]
    pub const fn mtime(&self) -> i64 {
        self.mtime
    }
    /// Raw tar type flag.
    #[must_use]
    pub const fn type_flag(&self) -> u8 {
        self.type_flag
    }
    /// Link target, when present.
    pub fn link_name(&self) -> Option<Cow<'_, Path>> {
        self.link_name.as_deref().map(bytes_to_path)
    }
}

struct ReaderState<R> {
    reader: R,
    raw_bytes: u64,
    pending: u64,
    padding: u64,
    generation: u64,
}

impl<R: Read> ReaderState<R> {
    fn read_counted(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.raw_bytes = self.raw_bytes.saturating_add(n as u64);
        Ok(n)
    }

    fn read_exact_counted(&mut self, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.read_counted(buf)?;
            if n == 0 {
                return Err(error(ErrorKind::UnexpectedEof, "truncated tar archive"));
            }
            buf = &mut buf[n..];
        }
        Ok(())
    }

    fn skip(&mut self, mut amount: u64) -> io::Result<()> {
        let mut buf = [0_u8; 8192];
        while amount != 0 {
            let want = usize::try_from(amount.min(buf.len() as u64)).unwrap_or(buf.len());
            self.read_exact_counted(&mut buf[..want])?;
            amount -= want as u64;
        }
        Ok(())
    }

    fn finish_entry(&mut self) -> io::Result<()> {
        self.skip(self.pending)?;
        self.pending = 0;
        self.skip(self.padding)?;
        self.padding = 0;
        Ok(())
    }

    fn read_entry_data(&mut self, generation: u64, buf: &mut [u8]) -> io::Result<usize> {
        if generation != self.generation {
            return Err(error(
                ErrorKind::InvalidInput,
                "entry is stale because iteration advanced",
            ));
        }
        let want = usize::try_from(self.pending.min(buf.len() as u64)).unwrap_or(buf.len());
        if want == 0 {
            return Ok(0);
        }
        let n = self.read_counted(&mut buf[..want])?;
        if n == 0 {
            return Err(error(ErrorKind::UnexpectedEof, "truncated entry data"));
        }
        self.pending -= n as u64;
        Ok(n)
    }
}

/// A tar archive over a non-seekable input stream.
pub struct Archive<R: Read> {
    state: Rc<RefCell<ReaderState<R>>>,
}

impl<R: Read> Archive<R> {
    /// Creates an archive reader. Compression must already have been removed.
    pub fn new(reader: R) -> Self {
        Self {
            state: Rc::new(RefCell::new(ReaderState {
                reader,
                raw_bytes: 0,
                pending: 0,
                padding: 0,
                generation: 0,
            })),
        }
    }

    /// Returns a streaming iterator over logical archive entries.
    ///
    /// # Errors
    ///
    /// Reserved for reader initialization errors in future versions.
    pub fn entries(&mut self) -> Result<Entries<'_, R>> {
        Ok(Entries {
            state: Rc::clone(&self.state),
            done: false,
            zero_blocks: 0,
            global_pax: BTreeMap::new(),
            local_pax: None,
            long_name: None,
            long_link: None,
            marker: PhantomData,
        })
    }

    /// Securely extracts this archive into `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed archives, unsafe paths, truncated input,
    /// callback-independent I/O failures, or filesystem extraction failures.
    pub fn unpack<P: AsRef<Path>>(
        mut self,
        dest: P,
        opts: &mut UnpackOptions,
    ) -> Result<UnpackSummary> {
        unpack_archive(&mut self, dest.as_ref(), opts)
    }
}

/// Streaming iterator returned by [`Archive::entries`].
pub struct Entries<'a, R: Read> {
    state: Rc<RefCell<ReaderState<R>>>,
    done: bool,
    zero_blocks: u8,
    global_pax: BTreeMap<String, Vec<u8>>,
    local_pax: Option<Vec<(String, Vec<u8>)>>,
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    marker: PhantomData<&'a mut Archive<R>>,
}

impl<R: Read> Iterator for Entries<'_, R> {
    type Item = Result<Entry<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }
}

impl<R: Read> Entries<'_, R> {
    #[allow(clippy::too_many_lines)]
    fn next_entry(&mut self) -> Result<Option<Entry<R>>> {
        loop {
            let mut block = [0_u8; 512];
            {
                let mut state = self.state.borrow_mut();
                state.finish_entry()?;
                state.generation = state.generation.wrapping_add(1);
                let mut first = [0_u8; 1];
                let n = state.read_counted(&mut first)?;
                if n == 0 {
                    return Ok(None);
                }
                block[0] = first[0];
                state.read_exact_counted(&mut block[1..])?;
            }
            if block.iter().all(|byte| *byte == 0) {
                self.zero_blocks += 1;
                if self.zero_blocks == 2 {
                    return Ok(None);
                }
                continue;
            }
            self.zero_blocks = 0;
            verify_checksum(&block)?;
            let mut header = parse_header(&block)?;
            let flag = header.type_flag;
            let size = header.stored_size;

            if matches!(flag, b'x' | b'g' | b'L' | b'K') {
                if size > MAX_PAX_SIZE {
                    return Err(error(
                        ErrorKind::InvalidData,
                        "tar metadata exceeds 1 MiB limit",
                    ));
                }
                let payload = self.read_metadata(size)?;
                match flag {
                    b'x' => {
                        if self.local_pax.is_some() {
                            return Err(invalid("two local PAX headers describe one entry"));
                        }
                        self.local_pax = Some(parse_pax(&payload)?);
                    }
                    b'g' => {
                        for (key, value) in parse_pax(&payload)? {
                            if value.is_empty() {
                                self.global_pax.remove(&key);
                            } else {
                                self.global_pax.insert(key, value);
                            }
                        }
                    }
                    b'L' => self.long_name = Some(trim_metadata(payload)),
                    b'K' => self.long_link = Some(trim_metadata(payload)),
                    _ => unreachable!(),
                }
                continue;
            }

            let mut pax: Vec<(String, Vec<u8>)> = self
                .global_pax
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if let Some(local) = self.local_pax.take() {
                pax.retain(|(existing, _)| !local.iter().any(|(key, _)| key == existing));
                pax.extend(local.into_iter().filter(|(_, value)| !value.is_empty()));
            }
            if let Some(name) = self.long_name.take() {
                header.path = name;
            }
            if let Some(link) = self.long_link.take() {
                header.link_name = Some(link);
            }
            apply_pax_header(&mut header, &pax)?;

            let physical_size = header.stored_size;
            let generation;
            {
                let mut state = self.state.borrow_mut();
                state.pending = physical_size;
                state.padding = padding(physical_size);
                generation = state.generation;
            }

            let (sparse, logical_size) = if flag == b'S' {
                self.parse_old_gnu_sparse(&block, physical_size)?
            } else {
                self.parse_pax_sparse(&pax, physical_size)?
            };
            if let Some(name) = pax_value(&pax, "GNU.sparse.name") {
                header.path = name.to_vec();
            }
            let kind = EntryType::from_flag(flag);
            return Ok(Some(Entry {
                state: Rc::clone(&self.state),
                header,
                kind,
                pax,
                sparse,
                logical_size,
                logical_pos: 0,
                sparse_index: 0,
                generation,
            }));
        }
    }

    fn read_metadata(&self, size: u64) -> Result<Vec<u8>> {
        let alloc =
            usize::try_from(size).map_err(|_| invalid("metadata size cannot fit in memory"))?;
        let mut payload = vec![0_u8; alloc];
        let mut state = self.state.borrow_mut();
        state.read_exact_counted(&mut payload)?;
        state.skip(padding(size))?;
        Ok(payload)
    }

    fn parse_old_gnu_sparse(
        &self,
        block: &[u8; 512],
        physical: u64,
    ) -> Result<(Option<Vec<SparseSegment>>, u64)> {
        if &block[257..265] != b"ustar  \0" {
            return Err(invalid("old GNU sparse entry lacks a GNU header"));
        }
        let mut map = Vec::new();
        for chunk in block[386..482].chunks_exact(24) {
            if !push_sparse_pair(&mut map, &chunk[..12], &chunk[12..])? {
                break;
            }
        }
        let mut extended = block[482] != 0;
        while extended {
            let mut ext = [0_u8; 512];
            self.state.borrow_mut().read_exact_counted(&mut ext)?;
            for chunk in ext[..504].chunks_exact(24) {
                if !push_sparse_pair(&mut map, &chunk[..12], &chunk[12..])? {
                    break;
                }
            }
            extended = ext[504] != 0;
            if map.len() > MAX_SPARSE_SEGMENTS {
                return Err(invalid("sparse map has too many segments"));
            }
        }
        let logical = parse_number(&block[483..495])?;
        validate_sparse(&map, logical, physical, true)?;
        Ok((Some(map), logical))
    }

    fn parse_pax_sparse(
        &self,
        pax: &[(String, Vec<u8>)],
        physical: u64,
    ) -> Result<(Option<Vec<SparseSegment>>, u64)> {
        let has_sparse = pax.iter().any(|(key, _)| key.starts_with("GNU.sparse."));
        if !has_sparse {
            return Ok((None, physical));
        }
        let major = pax_text_checked(pax, "GNU.sparse.major")?;
        let minor = pax_text_checked(pax, "GNU.sparse.minor")?;
        if major == Some("1") && minor == Some("0") {
            let logical = pax_u64_checked(pax, "GNU.sparse.realsize")?
                .ok_or_else(|| invalid("PAX sparse 1.0 lacks GNU.sparse.realsize"))?;
            let (map, map_bytes) = self.read_sparse_1_0_map()?;
            let packed = physical
                .checked_sub(map_bytes)
                .ok_or_else(|| invalid("sparse map exceeds entry size"))?;
            validate_sparse(&map, logical, packed, true)?;
            return Ok((Some(map), logical));
        }
        let is_version_zero = major == Some("0") && matches!(minor, Some("0" | "1"));
        if (major.is_some() || minor.is_some()) && !is_version_zero {
            return Err(invalid(
                "unsupported or contradictory GNU sparse PAX version",
            ));
        }
        let logical = pax_u64_checked(pax, "GNU.sparse.size")?
            .or(pax_u64_checked(pax, "GNU.sparse.realsize")?)
            .ok_or_else(|| invalid("GNU sparse PAX metadata lacks logical size"))?;
        let map = if let Some(value) = pax_text_checked(pax, "GNU.sparse.map")? {
            parse_sparse_csv(value)?
        } else if let Some(count) = pax_u64_checked(pax, "GNU.sparse.numblocks")? {
            parse_sparse_pairs(pax, count)?
        } else {
            return Err(invalid("orphaned GNU sparse PAX metadata"));
        };
        validate_sparse(&map, logical, physical, true)?;
        Ok((Some(map), logical))
    }

    fn read_sparse_1_0_map(&self) -> Result<(Vec<SparseSegment>, u64)> {
        let mut consumed = 0_u64;
        let count = self.read_sparse_line(&mut consumed)?;
        let count =
            usize::try_from(count).map_err(|_| invalid("sparse segment count is too large"))?;
        if count > MAX_SPARSE_SEGMENTS {
            return Err(invalid("sparse map has too many segments"));
        }
        let mut map = Vec::with_capacity(count);
        for _ in 0..count {
            let offset = self.read_sparse_line(&mut consumed)?;
            let len = self.read_sparse_line(&mut consumed)?;
            map.push(SparseSegment { offset, len });
        }
        let map_bytes = consumed
            .checked_add(padding(consumed))
            .ok_or_else(|| invalid("sparse map overflow"))?;
        let extra = map_bytes - consumed;
        let mut state = self.state.borrow_mut();
        if extra > state.pending {
            return Err(invalid("sparse map exceeds entry size"));
        }
        state.skip(extra)?;
        state.pending -= extra;
        Ok((map, map_bytes))
    }

    fn read_sparse_line(&self, consumed: &mut u64) -> Result<u64> {
        let mut digits = Vec::with_capacity(20);
        loop {
            let mut byte = [0_u8; 1];
            let mut state = self.state.borrow_mut();
            if state.pending == 0 {
                return Err(invalid("truncated GNU sparse 1.0 map"));
            }
            state.read_exact_counted(&mut byte)?;
            state.pending -= 1;
            drop(state);
            *consumed += 1;
            if byte[0] == b'\n' {
                break;
            }
            if !byte[0].is_ascii_digit() || digits.len() == 20 {
                return Err(invalid("invalid decimal in GNU sparse 1.0 map"));
            }
            digits.push(byte[0]);
        }
        if digits.is_empty() {
            return Err(invalid("empty decimal in GNU sparse 1.0 map"));
        }
        parse_decimal(&digits)
    }
}

/// A logical archive entry. Reading a sparse entry materializes holes as zeroes.
pub struct Entry<R: Read> {
    state: Rc<RefCell<ReaderState<R>>>,
    header: Header,
    kind: EntryType,
    pax: Vec<(String, Vec<u8>)>,
    sparse: Option<Vec<SparseSegment>>,
    logical_size: u64,
    logical_pos: u64,
    sparse_index: usize,
    generation: u64,
}

impl<R: Read> Entry<R> {
    /// Returns the parsed header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }
    /// Returns the final path after long-name, PAX, and sparse-name resolution.
    ///
    /// # Errors
    ///
    /// Reserved for platform-specific path conversion failures.
    pub fn path(&self) -> Result<Cow<'_, Path>> {
        Ok(bytes_to_path(&self.header.path))
    }
    /// Returns this entry's type.
    #[must_use]
    pub const fn entry_type(&self) -> EntryType {
        self.kind
    }
    /// Returns the logical size, including sparse holes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.logical_size
    }
    /// Returns data extents for a sparse entry, or `None` for a dense entry.
    #[must_use]
    pub fn sparse_map(&self) -> Option<&[SparseSegment]> {
        self.sparse.as_deref()
    }
    /// Iterates over effective PAX key/value records.
    pub fn pax_extensions(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.pax
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_slice()))
    }
    /// Returns cumulative raw bytes consumed from the underlying stream.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.state.borrow().raw_bytes
    }

    fn read_physical(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.state
            .borrow_mut()
            .read_entry_data(self.generation, buf)
    }

    fn copy_sparse_to(
        &mut self,
        file: &mut File,
        progress: &mut ProgressReporter<'_>,
    ) -> Result<()> {
        file.set_len(self.logical_size)?;
        let map = self.sparse.clone().unwrap_or_default();
        let mut buf = vec![0_u8; 64 * 1024];
        for segment in map {
            file.seek(SeekFrom::Start(segment.offset))?;
            let mut remaining = segment.len;
            while remaining != 0 {
                let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
                let n = self.read_physical(&mut buf[..want])?;
                if n == 0 {
                    return Err(error(ErrorKind::UnexpectedEof, "truncated sparse data"));
                }
                file.write_all(&buf[..n])?;
                remaining -= n as u64;
                progress.update(self.bytes_read());
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for Entry<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.logical_pos >= self.logical_size {
            return Ok(0);
        }
        let remaining = self.logical_size - self.logical_pos;
        let limit = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let Some(map) = self.sparse.as_ref() else {
            let n = self.read_physical(&mut buf[..limit])?;
            self.logical_pos += n as u64;
            return Ok(n);
        };
        while self.sparse_index < map.len()
            && self.logical_pos
                >= map[self.sparse_index]
                    .offset
                    .saturating_add(map[self.sparse_index].len)
        {
            self.sparse_index += 1;
        }
        if self.sparse_index == map.len() || self.logical_pos < map[self.sparse_index].offset {
            let hole_end = map
                .get(self.sparse_index)
                .map_or(self.logical_size, |segment| segment.offset);
            let n =
                usize::try_from((hole_end - self.logical_pos).min(limit as u64)).unwrap_or(limit);
            buf[..n].fill(0);
            self.logical_pos += n as u64;
            return Ok(n);
        }
        let segment_end = map[self.sparse_index].offset + map[self.sparse_index].len;
        let nmax =
            usize::try_from((segment_end - self.logical_pos).min(limit as u64)).unwrap_or(limit);
        let n = self.read_physical(&mut buf[..nmax])?;
        self.logical_pos += n as u64;
        Ok(n)
    }
}

fn parse_header(block: &[u8; 512]) -> Result<Header> {
    let mut path = nul_bytes(&block[..100]).to_vec();
    let magic = &block[257..263];
    let prefix = nul_bytes(&block[345..500]);
    if !prefix.is_empty() && magic == b"ustar\0" {
        let mut combined = prefix.to_vec();
        combined.push(b'/');
        combined.extend_from_slice(&path);
        path = combined;
    }
    let link = nul_bytes(&block[157..257]);
    Ok(Header {
        path,
        link_name: (!link.is_empty()).then(|| link.to_vec()),
        mode: u32::try_from(parse_number(&block[100..108])?)
            .map_err(|_| invalid("mode is too large"))?,
        uid: parse_number(&block[108..116])?,
        gid: parse_number(&block[116..124])?,
        stored_size: parse_number(&block[124..136])?,
        mtime: parse_signed_number(&block[136..148])?,
        type_flag: block[156],
    })
}

fn verify_checksum(block: &[u8; 512]) -> Result<()> {
    let expected = parse_number(&block[148..156])?;
    let unsigned: u64 = block
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    let signed: i64 = block
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            if (148..156).contains(&i) {
                i64::from(b' ')
            } else {
                i64::from(i8::from_ne_bytes([*byte]))
            }
        })
        .sum();
    if expected != unsigned && i64::try_from(expected).ok() != Some(signed) {
        return Err(invalid("tar header checksum mismatch"));
    }
    Ok(())
}

fn parse_number(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        if field[0] & 0x40 != 0 {
            return Err(invalid("negative binary number where unsigned expected"));
        }
        let mut value = u64::from(field[0] & 0x3f);
        for byte in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(*byte)))
                .ok_or_else(|| invalid("numeric field overflow"))?;
        }
        return Ok(value);
    }
    let trimmed = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Ok(0);
    }
    if trimmed.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return Err(invalid("invalid octal numeric field"));
    }
    trimmed.into_iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid("numeric field overflow"))
    })
}

fn parse_signed_number(field: &[u8]) -> Result<i64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) && field[0] & 0x40 != 0 {
        let mut bytes = [0xff_u8; 8];
        let source = if field.len() > 8 {
            &field[field.len() - 8..]
        } else {
            field
        };
        bytes[8 - source.len()..].copy_from_slice(source);
        bytes[8 - source.len()] &= 0x7f;
        return Ok(i64::from_be_bytes(bytes));
    }
    i64::try_from(parse_number(field)?).map_err(|_| invalid("signed numeric field overflow"))
}

fn parse_decimal(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(invalid("invalid decimal number"));
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid("decimal number overflow"))
    })
}

fn parse_pax(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        let space = data[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| invalid("malformed PAX record length"))?
            + cursor;
        let length = usize::try_from(parse_decimal(&data[cursor..space])?)
            .map_err(|_| invalid("PAX record length is too large"))?;
        if length == 0
            || cursor
                .checked_add(length)
                .is_none_or(|end| end > data.len())
        {
            return Err(invalid("PAX record exceeds extension body"));
        }
        let record = &data[space + 1..cursor + length];
        if record.last() != Some(&b'\n') {
            return Err(invalid("PAX record lacks newline"));
        }
        let body = &record[..record.len() - 1];
        let equals = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| invalid("PAX record lacks equals sign"))?;
        let key =
            std::str::from_utf8(&body[..equals]).map_err(|_| invalid("PAX key is not UTF-8"))?;
        if key.is_empty() {
            return Err(invalid("PAX key is empty"));
        }
        records.push((key.to_owned(), body[equals + 1..].to_vec()));
        cursor += length;
    }
    Ok(records)
}

fn apply_pax_header(header: &mut Header, pax: &[(String, Vec<u8>)]) -> Result<()> {
    if let Some(path) = pax_value(pax, "path") {
        header.path = path.to_vec();
    }
    if let Some(link) = pax_value(pax, "linkpath") {
        header.link_name = Some(link.to_vec());
    }
    if let Some(size) = pax_u64_checked(pax, "size")? {
        header.stored_size = size;
    }
    if let Some(mode) = pax_u64_checked(pax, "mode")? {
        header.mode = u32::try_from(mode).map_err(|_| invalid("PAX mode is too large"))?;
    }
    if let Some(uid) = pax_u64_checked(pax, "uid")? {
        header.uid = uid;
    }
    if let Some(gid) = pax_u64_checked(pax, "gid")? {
        header.gid = gid;
    }
    if let Some(mtime) = pax_text_checked(pax, "mtime")? {
        let integral = mtime.split('.').next().unwrap_or(mtime);
        header.mtime = integral.parse().map_err(|_| invalid("invalid PAX mtime"))?;
    }
    Ok(())
}

fn pax_value<'a>(pax: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    pax.iter()
        .rev()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_slice())
}
fn pax_text_checked<'a>(pax: &'a [(String, Vec<u8>)], key: &str) -> Result<Option<&'a str>> {
    pax_value(pax, key)
        .map(|value| {
            std::str::from_utf8(value).map_err(|_| invalid("PAX numeric value is not UTF-8"))
        })
        .transpose()
}
fn pax_u64_checked(pax: &[(String, Vec<u8>)], key: &str) -> Result<Option<u64>> {
    pax_value(pax, key).map(parse_decimal).transpose()
}

fn parse_sparse_csv(value: &str) -> Result<Vec<SparseSegment>> {
    let values = value
        .split(',')
        .map(|part| parse_decimal(part.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    if values.len() % 2 != 0 {
        return Err(invalid("GNU.sparse.map has an odd value count"));
    }
    if values.len() / 2 > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|pair| SparseSegment {
            offset: pair[0],
            len: pair[1],
        })
        .collect())
}

fn parse_sparse_pairs(pax: &[(String, Vec<u8>)], count: u64) -> Result<Vec<SparseSegment>> {
    let count = usize::try_from(count).map_err(|_| invalid("sparse segment count is too large"))?;
    if count > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    let mut pairs = pax
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "GNU.sparse.offset" | "GNU.sparse.numbytes"));
    let mut map = Vec::with_capacity(count);
    for _ in 0..count {
        let offset = pairs
            .next()
            .filter(|(key, _)| key == "GNU.sparse.offset")
            .ok_or_else(|| invalid("sparse offset/length records are missing or out of order"))?;
        let length = pairs
            .next()
            .filter(|(key, _)| key == "GNU.sparse.numbytes")
            .ok_or_else(|| invalid("sparse offset/length records are missing or out of order"))?;
        map.push(SparseSegment {
            offset: parse_decimal(&offset.1)?,
            len: parse_decimal(&length.1)?,
        });
    }
    if pairs.next().is_some() {
        return Err(invalid("sparse map has too many pairs"));
    }
    Ok(map)
}

fn push_sparse_pair(map: &mut Vec<SparseSegment>, offset: &[u8], len: &[u8]) -> Result<bool> {
    if offset.first() == Some(&0) {
        return Ok(false);
    }
    let offset = parse_number(offset)?;
    let len = parse_number(len)?;
    map.push(SparseSegment { offset, len });
    Ok(true)
}

fn validate_sparse(map: &[SparseSegment], logical: u64, packed: u64, exact: bool) -> Result<()> {
    if map.len() > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    let mut previous_end = 0_u64;
    let mut total = 0_u64;
    for segment in map {
        let end = segment
            .offset
            .checked_add(segment.len)
            .ok_or_else(|| invalid("sparse segment overflows"))?;
        if segment.offset < previous_end || end > logical {
            return Err(invalid("sparse segments overlap or exceed logical size"));
        }
        total = total
            .checked_add(segment.len)
            .ok_or_else(|| invalid("sparse packed size overflows"))?;
        previous_end = end;
    }
    if (exact && total != packed) || (!exact && total > packed) {
        return Err(invalid("sparse map does not match packed entry size"));
    }
    Ok(())
}

fn trim_metadata(mut data: Vec<u8>) -> Vec<u8> {
    while data.last().is_some_and(|byte| *byte == 0 || *byte == b'\n') {
        data.pop();
    }
    data
}
fn nul_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())]
}
fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}
fn invalid(message: &'static str) -> io::Error {
    error(ErrorKind::InvalidData, message)
}
fn error(kind: ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

#[cfg(unix)]
fn bytes_to_path(bytes: &[u8]) -> Cow<'_, Path> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(Path::new(std::ffi::OsStr::from_bytes(bytes)))
}
#[cfg(not(unix))]
fn bytes_to_path(bytes: &[u8]) -> Cow<'_, Path> {
    Cow::Owned(PathBuf::from(String::from_utf8_lossy(bytes).into_owned()))
}

/// Progress notification containing raw input bytes consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Cumulative bytes pulled from the underlying reader.
    pub bytes_read: u64,
}

/// Metadata sent immediately before extracting an entry.
#[derive(Clone, Debug)]
pub struct EntryInfo {
    /// Final resolved archive path before component stripping.
    pub path: PathBuf,
    /// Entry kind.
    pub entry_type: EntryType,
    /// Logical entry size.
    pub size: u64,
    /// Whether the entry is sparse.
    pub sparse: bool,
}

/// Why an entry was skipped during extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SkipReason {
    /// Component stripping removed the entire path.
    Stripped,
    /// The path is reserved by the target platform.
    ReservedName,
    /// The entry type is not extracted by this crate.
    UnsupportedType,
    /// An existing path was retained because overwrite is disabled.
    Exists,
    /// Symlink creation is unavailable or was denied.
    SymlinkUnavailable,
}

/// One skipped archive entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedEntry {
    /// Original resolved entry path.
    pub path: PathBuf,
    /// Skip reason.
    pub reason: SkipReason,
}

/// Aggregate result of an extraction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnpackSummary {
    /// Regular files extracted.
    pub files: u64,
    /// Directories extracted or confirmed.
    pub dirs: u64,
    /// Symbolic links created.
    pub symlinks: u64,
    /// Hard links created.
    pub hardlinks: u64,
    /// Sparse regular files extracted.
    pub sparse_files: u64,
    /// Entries skipped, with reasons.
    pub skipped: Vec<SkippedEntry>,
}

/// Secure extraction behavior and callbacks.
#[non_exhaustive]
pub struct UnpackOptions {
    /// Leading path components removed after all name overrides are resolved.
    pub strip_components: usize,
    /// Restore entry modification times.
    pub preserve_mtime: bool,
    /// Restore Unix permission bits.
    pub preserve_permissions: bool,
    /// Replace existing non-directory entries.
    pub overwrite: bool,
    /// Raw-input progress callback.
    pub on_progress: Option<ProgressCallback>,
    /// Callback fired before each logical entry is handled.
    pub on_entry: Option<EntryCallback>,
}

/// Boxed raw-input progress callback.
pub type ProgressCallback = Box<dyn FnMut(Progress)>;
/// Boxed logical-entry callback.
pub type EntryCallback = Box<dyn FnMut(&EntryInfo)>;

impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            strip_components: 0,
            preserve_mtime: true,
            preserve_permissions: true,
            overwrite: true,
            on_progress: None,
            on_entry: None,
        }
    }
}

struct ProgressReporter<'a> {
    callback: &'a mut Option<ProgressCallback>,
    last: u64,
}

impl ProgressReporter<'_> {
    fn update(&mut self, current: u64) {
        if current.saturating_sub(self.last) >= 64 * 1024 {
            self.fire(current);
        }
    }
    fn boundary(&mut self, current: u64) {
        self.fire(current);
    }
    fn fire(&mut self, current: u64) {
        if let Some(callback) = self.callback.as_mut() {
            callback(Progress {
                bytes_read: current,
            });
        }
        self.last = current;
    }
}

#[allow(clippy::too_many_lines)]
fn unpack_archive<R: Read>(
    archive: &mut Archive<R>,
    dest: &Path,
    opts: &mut UnpackOptions,
) -> Result<UnpackSummary> {
    fs::create_dir_all(dest)?;
    if fs::symlink_metadata(dest)?.file_type().is_symlink() {
        return Err(invalid("destination may not be a symlink"));
    }
    let root = fs::canonicalize(dest)?;
    let mut summary = UnpackSummary::default();
    let mut deferred_dirs = Vec::new();
    let preserve_permissions = opts.preserve_permissions;
    let preserve_mtime = opts.preserve_mtime;
    let mut progress = ProgressReporter {
        callback: &mut opts.on_progress,
        last: 0,
    };
    let mut entries = archive.entries()?;
    for item in &mut entries {
        let mut entry = item?;
        let original = entry.path()?.into_owned();
        if let Some(callback) = opts.on_entry.as_mut() {
            callback(&EntryInfo {
                path: original.clone(),
                entry_type: entry.kind,
                size: entry.logical_size,
                sparse: entry.sparse.is_some(),
            });
        }
        progress.boundary(entry.bytes_read());
        let Some(relative) = secure_relative_path(&original, opts.strip_components)? else {
            summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::Stripped,
            });
            continue;
        };
        if is_reserved_path(&relative) {
            summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::ReservedName,
            });
            continue;
        }
        let output = root.join(&relative);
        ensure_safe_parents(&root, &relative)?;
        match entry.kind {
            EntryType::Directory => {
                if output.exists() && fs::symlink_metadata(&output)?.file_type().is_symlink() {
                    return Err(invalid("archive directory collides with symlink"));
                }
                fs::create_dir_all(&output)?;
                deferred_dirs.push((output, entry.header.mode, entry.header.mtime));
                summary.dirs += 1;
            }
            EntryType::File => {
                if !prepare_output(&output, opts.overwrite)? {
                    summary.skipped.push(SkippedEntry {
                        path: original,
                        reason: SkipReason::Exists,
                    });
                    continue;
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)?;
                if entry.sparse.is_some() {
                    entry.copy_sparse_to(&mut file, &mut progress)?;
                    summary.sparse_files += 1;
                } else {
                    let mut buf = vec![0_u8; 64 * 1024];
                    loop {
                        let n = entry.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        file.write_all(&buf[..n])?;
                        progress.update(entry.bytes_read());
                    }
                }
                apply_metadata(
                    &output,
                    entry.header.mode,
                    entry.header.mtime,
                    preserve_permissions,
                    preserve_mtime,
                )?;
                summary.files += 1;
            }
            EntryType::Symlink => {
                if !prepare_output(&output, opts.overwrite)? {
                    summary.skipped.push(SkippedEntry {
                        path: original,
                        reason: SkipReason::Exists,
                    });
                    continue;
                }
                let target = entry
                    .header
                    .link_name()
                    .ok_or_else(|| invalid("symlink lacks target"))?;
                match create_symlink(&target, &output) {
                    Ok(()) => summary.symlinks += 1,
                    Err(err)
                        if cfg!(windows)
                            && matches!(
                                err.kind(),
                                ErrorKind::PermissionDenied | ErrorKind::Unsupported
                            ) =>
                    {
                        summary.skipped.push(SkippedEntry {
                            path: original,
                            reason: SkipReason::SymlinkUnavailable,
                        });
                    }
                    Err(err) => return Err(err),
                }
            }
            EntryType::Hardlink => {
                if !prepare_output(&output, opts.overwrite)? {
                    summary.skipped.push(SkippedEntry {
                        path: original,
                        reason: SkipReason::Exists,
                    });
                    continue;
                }
                let target = entry
                    .header
                    .link_name()
                    .ok_or_else(|| invalid("hardlink lacks target"))?;
                let target_relative = secure_relative_path(&target, opts.strip_components)?
                    .ok_or_else(|| invalid("hardlink target was stripped away"))?;
                ensure_safe_parents(&root, &target_relative)?;
                let source = root.join(target_relative);
                let metadata = fs::symlink_metadata(&source)
                    .map_err(|_| invalid("hardlink target does not exist within destination"))?;
                if metadata.file_type().is_symlink() {
                    return Err(invalid("hardlink target may not be a symlink"));
                }
                fs::hard_link(source, output)?;
                summary.hardlinks += 1;
            }
            _ => summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::UnsupportedType,
            }),
        }
        progress.boundary(entry.bytes_read());
    }
    for (path, mode, mtime) in deferred_dirs.into_iter().rev() {
        apply_metadata(&path, mode, mtime, preserve_permissions, preserve_mtime)?;
    }
    progress.boundary(archive.state.borrow().raw_bytes);
    Ok(summary)
}

fn secure_relative_path(path: &Path, strip: usize) -> Result<Option<PathBuf>> {
    if path.is_absolute() {
        return Err(invalid("absolute archive path rejected"));
    }
    let mut clean = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => clean.push(value.to_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid("archive path traversal rejected"));
            }
        }
    }
    if strip >= clean.len() {
        return Ok(None);
    }
    Ok(Some(clean.into_iter().skip(strip).collect()))
}

fn ensure_safe_parents(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(part) = component else {
                return Err(invalid("invalid output path component"));
            };
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(invalid("archive attempted to write through a symlink"));
                }
                Ok(meta) if !meta.is_dir() => {
                    return Err(invalid("archive parent is not a directory"));
                }
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => fs::create_dir(&current)?,
                Err(err) => return Err(err),
            }
        }
    }
    Ok(())
}

fn prepare_output(path: &Path, overwrite: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_meta) if !overwrite => Ok(false),
        Ok(meta) if meta.is_dir() => Err(invalid("archive file collides with existing directory")),
        Ok(_) => {
            fs::remove_file(path)?;
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err),
    }
}

fn apply_metadata(
    path: &Path,
    mode: u32,
    mtime: i64,
    preserve_permissions: bool,
    preserve_mtime: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    let _ = (mode, preserve_permissions);
    #[cfg(unix)]
    if preserve_permissions {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if preserve_mtime {
        let time = filetime::FileTime::from_unix_time(mtime, 0);
        filetime::set_file_mtime(path, time)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &Path, output: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, output)
}
#[cfg(windows)]
fn create_symlink(target: &Path, output: &Path) -> Result<()> {
    std::os::windows::fs::symlink_file(target, output)
}

#[cfg(windows)]
fn is_reserved_path(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        let value = value.to_string_lossy();
        let stem = value
            .trim_end_matches([' ', '.'])
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
    })
}
#[cfg(not(windows))]
fn is_reserved_path(_path: &Path) -> bool {
    false
}
