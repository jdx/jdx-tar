use super::format::path_requires_directory;
use super::{Archive, Entry, EntryType, Result, error, invalid};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

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

/// Stateful secure extractor for callers that inspect or skip individual
/// entries before unpacking them.
///
/// Call [`Self::finish`] after the final entry so directory permissions and
/// modification times are applied after their children have been written.
#[must_use = "call finish() to apply deferred directory metadata"]
pub struct EntryUnpacker<'a> {
    root: PathBuf,
    opts: &'a mut UnpackOptions,
    deferred_dirs: Vec<DeferredDirectory>,
}

pub(super) struct DeferredDirectory {
    path: PathBuf,
    mode: u32,
    mtime: i64,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl DeferredDirectory {
    fn new(path: PathBuf, mode: u32, mtime: i64) -> Result<Self> {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() {
            return Err(invalid("archive directory is not a directory"));
        }
        Ok(Self {
            path,
            mode,
            mtime,
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl<'a> EntryUnpacker<'a> {
    /// Creates a per-entry extractor rooted at `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination cannot be created or resolved,
    /// or when it is itself a symbolic link.
    pub fn new<P: AsRef<Path>>(dest: P, opts: &'a mut UnpackOptions) -> Result<Self> {
        let dest = dest.as_ref();
        fs::create_dir_all(dest)?;
        if fs::symlink_metadata(dest)?.file_type().is_symlink() {
            return Err(invalid("destination may not be a symlink"));
        }
        Ok(Self {
            root: fs::canonicalize(dest)?,
            opts,
            deferred_dirs: Vec::new(),
        })
    }

    /// Securely extracts one entry beneath the configured destination.
    ///
    /// Entries may be inspected and omitted by the caller before invoking
    /// this method. Absolute paths, traversal, and writes through symlinked
    /// parents are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, malformed link target, truncated
    /// data, callback-independent I/O failure, or filesystem extraction
    /// failure, or if the entry is stale, already read, or previously extracted.
    pub fn unpack<R: Read>(&mut self, entry: &mut Entry<R>) -> Result<UnpackSummary> {
        unpack_entry(entry, &self.root, self.opts, &mut self.deferred_dirs)
    }

    /// Applies deferred directory metadata and completes extraction.
    ///
    /// # Errors
    ///
    /// Returns an error when directory permissions or modification times
    /// cannot be restored.
    pub fn finish(self) -> Result<()> {
        apply_deferred_directory_metadata(
            self.deferred_dirs,
            self.opts.preserve_permissions,
            self.opts.preserve_mtime,
        )
    }
}

pub(super) struct ProgressReporter<'a> {
    callback: &'a mut Option<ProgressCallback>,
    last: u64,
}

impl ProgressReporter<'_> {
    pub(super) fn update(&mut self, current: u64) {
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
pub(super) fn unpack_archive<R: Read>(
    archive: &mut Archive<R>,
    dest: &Path,
    opts: &mut UnpackOptions,
) -> Result<UnpackSummary> {
    let mut entries = archive.entries()?;
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
    for item in &mut entries {
        let mut entry = item?;
        validate_directory_suffixes(&entry)?;
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
        if matches!(
            entry.kind,
            EntryType::CharDevice | EntryType::BlockDevice | EntryType::Fifo
        ) {
            summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::UnsupportedType,
            });
            continue;
        }
        let output = root.join(&relative);
        if matches!(entry.kind, EntryType::Hardlink | EntryType::Symlink)
            && skip_existing_output(&root, &relative, opts.overwrite)?
        {
            summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::Exists,
            });
            continue;
        }
        let hardlink_source = if entry.kind == EntryType::Hardlink {
            Some(preflight_hardlink_source(
                &entry,
                &root,
                &output,
                opts.strip_components,
            )?)
        } else {
            None
        };
        validate_mtime_before_output(
            entry.kind,
            entry.header.mtime,
            opts.preserve_mtime,
            &output,
            opts.overwrite,
        )?;
        if entry.kind == EntryType::File
            && entry.sparse.is_some()
            && entry.logical_size > i64::MAX as u64
            && (opts.overwrite || fs::symlink_metadata(&output).is_err())
        {
            return Err(invalid(
                "sparse output length exceeds the filesystem offset range",
            ));
        }
        ensure_safe_parents(&root, &relative)?;
        match entry.kind {
            EntryType::Directory => {
                if output.exists() && fs::symlink_metadata(&output)?.file_type().is_symlink() {
                    return Err(invalid("archive directory collides with symlink"));
                }
                fs::create_dir_all(&output)?;
                deferred_dirs.push(DeferredDirectory::new(
                    output,
                    entry.header.mode,
                    entry.header.mtime,
                )?);
                summary.dirs += 1;
            }
            EntryType::File | EntryType::Other(_) => {
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
                apply_file_metadata(
                    &file,
                    entry.header.mode,
                    entry.header.mtime,
                    preserve_permissions,
                    preserve_mtime,
                )?;
                summary.files += 1;
            }
            EntryType::Symlink => {
                let target = entry
                    .header
                    .link_name()
                    .ok_or_else(|| invalid("symlink lacks target"))?;
                match replace_output_with_link(&output, opts.overwrite, |path| {
                    create_symlink(&target, path)
                }) {
                    Ok(true) => summary.symlinks += 1,
                    Ok(false) => {
                        summary.skipped.push(SkippedEntry {
                            path: original,
                            reason: SkipReason::Exists,
                        });
                        continue;
                    }
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
                let source = hardlink_source
                    .as_ref()
                    .ok_or_else(|| invalid("hardlink source was not prepared"))?;
                if !replace_output_with_link(&output, opts.overwrite, |path| {
                    fs::hard_link(source, path)
                })? {
                    summary.skipped.push(SkippedEntry {
                        path: original,
                        reason: SkipReason::Exists,
                    });
                    continue;
                }
                summary.hardlinks += 1;
            }
            _ => summary.skipped.push(SkippedEntry {
                path: original,
                reason: SkipReason::UnsupportedType,
            }),
        }
        progress.boundary(entry.bytes_read());
    }
    apply_deferred_directory_metadata(deferred_dirs, preserve_permissions, preserve_mtime)?;
    progress.boundary(archive.state.borrow().raw_bytes);
    Ok(summary)
}

#[allow(clippy::too_many_lines)]
pub(super) fn unpack_entry<R: Read>(
    entry: &mut Entry<R>,
    root: &Path,
    opts: &mut UnpackOptions,
    deferred_dirs: &mut Vec<DeferredDirectory>,
) -> Result<UnpackSummary> {
    if entry.generation != entry.state.borrow().generation {
        return Err(error(
            ErrorKind::InvalidInput,
            "entry is stale because iteration advanced",
        ));
    }
    if entry.logical_pos != 0 || entry.extraction_started {
        return Err(error(
            ErrorKind::InvalidInput,
            "entry was already read or extraction was started",
        ));
    }
    validate_directory_suffixes(entry)?;
    let original = entry.path()?.into_owned();
    if let Some(callback) = opts.on_entry.as_mut() {
        callback(&EntryInfo {
            path: original.clone(),
            entry_type: entry.kind,
            size: entry.logical_size,
            sparse: entry.sparse.is_some(),
        });
    }
    let mut summary = UnpackSummary::default();
    let mut progress = ProgressReporter {
        callback: &mut opts.on_progress,
        last: 0,
    };
    progress.boundary(entry.bytes_read());
    let Some(relative) = secure_relative_path(&original, opts.strip_components)? else {
        summary.skipped.push(SkippedEntry {
            path: original,
            reason: SkipReason::Stripped,
        });
        return Ok(summary);
    };
    if is_reserved_path(&relative) {
        summary.skipped.push(SkippedEntry {
            path: original,
            reason: SkipReason::ReservedName,
        });
        return Ok(summary);
    }
    if matches!(
        entry.kind,
        EntryType::CharDevice | EntryType::BlockDevice | EntryType::Fifo
    ) {
        summary.skipped.push(SkippedEntry {
            path: original,
            reason: SkipReason::UnsupportedType,
        });
        return Ok(summary);
    }
    let output = root.join(&relative);
    if matches!(entry.kind, EntryType::Hardlink | EntryType::Symlink)
        && skip_existing_output(root, &relative, opts.overwrite)?
    {
        summary.skipped.push(SkippedEntry {
            path: original,
            reason: SkipReason::Exists,
        });
        return Ok(summary);
    }
    let hardlink_source = if entry.kind == EntryType::Hardlink {
        Some(preflight_hardlink_source(
            entry,
            root,
            &output,
            opts.strip_components,
        )?)
    } else {
        None
    };
    validate_mtime_before_output(
        entry.kind,
        entry.header.mtime,
        opts.preserve_mtime,
        &output,
        opts.overwrite,
    )?;
    if entry.kind == EntryType::File
        && entry.sparse.is_some()
        && entry.logical_size > i64::MAX as u64
        && (opts.overwrite || fs::symlink_metadata(&output).is_err())
    {
        return Err(invalid(
            "sparse output length exceeds the filesystem offset range",
        ));
    }
    ensure_safe_parents(root, &relative)?;
    match entry.kind {
        EntryType::Directory => {
            if output.exists() && fs::symlink_metadata(&output)?.file_type().is_symlink() {
                return Err(invalid("archive directory collides with symlink"));
            }
            entry.extraction_started = true;
            fs::create_dir_all(&output)?;
            deferred_dirs.push(DeferredDirectory::new(
                output,
                entry.header.mode,
                entry.header.mtime,
            )?);
            summary.dirs = 1;
        }
        EntryType::File | EntryType::Other(_) => {
            if !prepare_output(&output, opts.overwrite)? {
                summary.skipped.push(SkippedEntry {
                    path: original,
                    reason: SkipReason::Exists,
                });
                return Ok(summary);
            }
            // Sparse copying and zero-sized entries do not advance logical_pos.
            // Once output preparation succeeds, even a failed copy is consumed.
            entry.extraction_started = true;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            if entry.sparse.is_some() {
                entry.copy_sparse_to(&mut file, &mut progress)?;
                summary.sparse_files = 1;
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
            apply_file_metadata(
                &file,
                entry.header.mode,
                entry.header.mtime,
                opts.preserve_permissions,
                opts.preserve_mtime,
            )?;
            summary.files = 1;
        }
        EntryType::Symlink => {
            let target = entry
                .header
                .link_name()
                .ok_or_else(|| invalid("symlink lacks target"))?;
            match replace_output_with_link(&output, opts.overwrite, |path| {
                create_symlink(&target, path)
            }) {
                Ok(true) => {
                    entry.extraction_started = true;
                    summary.symlinks = 1;
                }
                Ok(false) => {
                    summary.skipped.push(SkippedEntry {
                        path: original,
                        reason: SkipReason::Exists,
                    });
                    return Ok(summary);
                }
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
            let source = hardlink_source
                .as_ref()
                .ok_or_else(|| invalid("hardlink source was not prepared"))?;
            if !replace_output_with_link(&output, opts.overwrite, |path| {
                fs::hard_link(source, path)
            })? {
                summary.skipped.push(SkippedEntry {
                    path: original,
                    reason: SkipReason::Exists,
                });
                return Ok(summary);
            }
            entry.extraction_started = true;
            summary.hardlinks = 1;
        }
        _ => summary.skipped.push(SkippedEntry {
            path: original,
            reason: SkipReason::UnsupportedType,
        }),
    }
    progress.boundary(entry.bytes_read());
    Ok(summary)
}

fn validate_directory_suffixes<R: Read>(entry: &Entry<R>) -> Result<()> {
    if entry.kind != EntryType::Directory && path_requires_directory(&entry.header.path) {
        return Err(invalid(
            "only a directory may have a directory-required path suffix",
        ));
    }
    if entry.kind == EntryType::Hardlink
        && entry
            .header
            .link_name
            .as_deref()
            .is_some_and(path_requires_directory)
    {
        return Err(invalid("hardlink target requires a directory"));
    }
    Ok(())
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

fn preflight_hardlink_source<R: Read>(
    entry: &Entry<R>,
    root: &Path,
    output: &Path,
    strip_components: usize,
) -> Result<PathBuf> {
    let target = entry
        .header
        .link_name()
        .ok_or_else(|| invalid("hardlink lacks target"))?;
    let relative = secure_relative_path(&target, strip_components)?
        .ok_or_else(|| invalid("hardlink target was stripped away"))?;
    let mut source = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        // A missing source is an error, never a reason to create its parents.
        for component in parent.components() {
            source.push(component);
            let metadata = fs::symlink_metadata(&source)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(invalid("hardlink target parent is not a safe directory"));
            }
        }
    }
    source = root.join(relative);
    let metadata = fs::symlink_metadata(&source)?;
    if !metadata.is_file() {
        return Err(invalid("hardlink target must be an existing regular file"));
    }
    match fs::symlink_metadata(output) {
        Ok(metadata) if !metadata.file_type().is_symlink() => {
            // Distinct hard links to one inode are safe; the same pathname is
            // not, including filesystem case and Unicode aliases.
            if fs::canonicalize(output)? == fs::canonicalize(&source)? {
                return Err(invalid("hardlink target resolves to its output path"));
            }
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    Ok(source)
}

struct TemporaryLink(PathBuf);

impl Drop for TemporaryLink {
    fn drop(&mut self) {
        // A successful rename normally removes this name. It can also be a
        // no-op when both names already refer to the same hard-linked inode.
        let _ = fs::remove_file(&self.0);
    }
}

fn replace_output_with_link(
    path: &Path,
    overwrite: bool,
    create: impl Fn(&Path) -> Result<()>,
) -> Result<bool> {
    static NEXT_LINK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    match fs::symlink_metadata(path) {
        Ok(_) if !overwrite => return Ok(false),
        Ok(metadata) if metadata.is_dir() => {
            return Err(invalid("archive file collides with existing directory"));
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {
            create(path)?;
            return Ok(true);
        }
        Err(err) => return Err(err),
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("link output has no parent directory"))?;
    for _ in 0..128 {
        let id = NEXT_LINK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = parent.join(format!(".jdx-tar-{}-{id}.link", std::process::id()));
        match create(&temporary) {
            Ok(()) => {
                let temporary = TemporaryLink(temporary);
                // The destination is untouched until the OS has accepted the
                // replacement link; a sibling rename commits the change.
                fs::rename(&temporary.0, path)?;
                return Ok(true);
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "unable to reserve a temporary link name",
    ))
}

fn skip_existing_output(root: &Path, relative: &Path, overwrite: bool) -> Result<bool> {
    if overwrite {
        return Ok(false);
    }
    match fs::symlink_metadata(root.join(relative)) {
        Ok(_) => {
            // An existing leaf does not authorize traversal through a symlinked
            // parent. Its parents already exist, so this check creates none.
            ensure_safe_parents(root, relative)?;
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
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

fn apply_deferred_directory_metadata(
    directories: Vec<DeferredDirectory>,
    preserve_permissions: bool,
    preserve_mtime: bool,
) -> Result<()> {
    // Canonical paths coalesce case and Unicode aliases on filesystems that
    // resolve those spellings to the same directory. The last member wins.
    let mut latest = std::collections::BTreeMap::new();
    for directory in directories {
        latest.insert(directory.path.clone(), directory);
    }
    let mut directories: Vec<_> = latest.into_iter().collect();
    directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (_, directory) in directories {
        apply_directory_metadata(&directory, preserve_permissions, preserve_mtime)?;
    }
    Ok(())
}

fn apply_file_metadata(
    file: &fs::File,
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
        file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if preserve_mtime {
        let time = filetime::FileTime::from_unix_time(mtime, 0);
        filetime::set_file_handle_times(file, None, Some(time))?;
    }
    Ok(())
}

fn apply_directory_metadata(
    directory: &DeferredDirectory,
    preserve_permissions: bool,
    preserve_mtime: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    let _ = directory.mode;
    if !preserve_permissions && !preserve_mtime {
        return Ok(());
    }
    #[cfg(unix)]
    let metadata = {
        let metadata = fs::symlink_metadata(&directory.path)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != directory.identity {
            return Err(invalid(
                "archive directory changed before metadata restoration",
            ));
        }
        metadata
    };
    #[cfg(unix)]
    if preserve_permissions {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &directory.path,
            fs::Permissions::from_mode(directory.mode & 0o7777),
        )?;
    }
    if preserve_mtime {
        let time = filetime::FileTime::from_unix_time(directory.mtime, 0);
        #[cfg(unix)]
        {
            // Restore time without reopening a directory whose archived mode
            // can remove all access. The captured identity is checked after
            // callbacks; concurrent tree mutation remains outside the contract.
            filetime::set_symlink_file_times(
                &directory.path,
                filetime::FileTime::from_last_access_time(&metadata),
                time,
            )?;
        }
        #[cfg(not(unix))]
        filetime::set_file_mtime(&directory.path, time)?;
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

fn validate_mtime_before_output(
    kind: EntryType,
    mtime: i64,
    preserve_mtime: bool,
    output: &Path,
    overwrite: bool,
) -> Result<()> {
    let skips_existing_file =
        kind == EntryType::File && !overwrite && fs::symlink_metadata(output).is_ok();
    if preserve_mtime
        && matches!(kind, EntryType::File | EntryType::Directory)
        && mtime == i64::MIN
        && !skips_existing_file
    {
        return Err(invalid("tar mtime is too small to restore safely"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn normalizes_and_strips_safe_paths() {
        assert_eq!(
            secure_relative_path(Path::new("./one/two/file"), 2).unwrap(),
            Some(PathBuf::from("file"))
        );
        assert_eq!(secure_relative_path(Path::new("one"), 1).unwrap(), None);
        assert!(secure_relative_path(Path::new("../file"), 0).is_err());
        assert!(secure_relative_path(Path::new("/file"), 0).is_err());
    }

    #[test]
    fn progress_reports_thresholds_and_boundaries() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let mut callback: Option<ProgressCallback> = Some(Box::new({
            let seen = Rc::clone(&seen);
            move |progress| seen.borrow_mut().push(progress.bytes_read)
        }));
        let mut reporter = ProgressReporter {
            callback: &mut callback,
            last: 0,
        };
        reporter.update(64 * 1024 - 1);
        assert!(seen.borrow().is_empty());
        reporter.update(64 * 1024);
        reporter.boundary(70 * 1024);
        assert_eq!(*seen.borrow(), [64 * 1024, 70 * 1024]);
    }

    #[test]
    fn prepare_output_respects_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, b"old").unwrap();
        assert!(!prepare_output(&path, false).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(prepare_output(&path, true).unwrap());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("link")).unwrap();
        assert!(ensure_safe_parents(temp.path(), Path::new("link/file")).is_err());
    }

    #[test]
    fn reserved_names_follow_platform_rules() {
        assert_eq!(is_reserved_path(Path::new("CON.txt")), cfg!(windows));
        assert!(!is_reserved_path(Path::new("ordinary.txt")));
    }
}
