//! A secure, synchronous, streaming tar reader, writer, and extractor.
//!
//! This crate reads already-decompressed tar streams and supports all GNU
//! sparse formats commonly found in release archives.

mod builder;
mod format;
mod unpack;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

pub use builder::Builder;
use format::{
    apply_pax_header, bytes_to_path, parse_decimal, parse_header, parse_number, parse_pax,
    parse_sparse_csv, parse_sparse_pairs, pax_text_checked, pax_u64_checked, pax_value,
    push_sparse_pair, trim_metadata, validate_sparse, verify_checksum,
};
pub use unpack::{
    EntryCallback, EntryInfo, EntryUnpacker, Progress, ProgressCallback, SkipReason, SkippedEntry,
    UnpackOptions, UnpackSummary,
};
use unpack::{ProgressReporter, unpack_archive};

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

    const fn type_flag(self) -> u8 {
        match self {
            Self::File => b'0',
            Self::Directory => b'5',
            Self::Symlink => b'2',
            Self::Hardlink => b'1',
            Self::CharDevice => b'3',
            Self::BlockDevice => b'4',
            Self::Fifo => b'6',
            Self::Other(flag) => flag,
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
    /// Creates a deterministic GNU-format header for `entry_type`.
    ///
    /// Numeric fields default to zero. Callers must set the entry size before
    /// appending regular-file data. Paths and checksums are populated by
    /// [`Builder`].
    #[must_use]
    pub fn new_gnu(entry_type: EntryType) -> Self {
        Self {
            path: Vec::new(),
            link_name: None,
            mode: 0,
            uid: 0,
            gid: 0,
            stored_size: 0,
            mtime: 0,
            type_flag: entry_type.type_flag(),
        }
    }

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

    /// Sets the file mode stored in the header.
    pub const fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
    }

    /// Sets the numeric user id stored in the header.
    pub const fn set_uid(&mut self, uid: u64) {
        self.uid = uid;
    }

    /// Sets the numeric group id stored in the header.
    pub const fn set_gid(&mut self, gid: u64) {
        self.gid = gid;
    }

    /// Sets the number of data bytes that follow the header.
    pub const fn set_size(&mut self, size: u64) {
        self.stored_size = size;
    }

    /// Sets the modification time as seconds since the Unix epoch.
    pub const fn set_mtime(&mut self, mtime: i64) {
        self.mtime = mtime;
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

            // GNU sparse PAX archives use the tar header's size for the packed
            // body. Some writers (notably Go's archive/tar) also emit a PAX
            // `size` record containing the logical sparse size.
            let physical_size = if pax.iter().any(|(key, _)| key.starts_with("GNU.sparse.")) {
                size
            } else {
                header.stored_size
            };
            header.stored_size = physical_size;
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

fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}
fn invalid(message: &'static str) -> io::Error {
    error(ErrorKind::InvalidData, message)
}
fn error(kind: ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}
