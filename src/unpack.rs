use super::{Archive, Entry, EntryType, Result, invalid};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
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
    deferred_dirs: Vec<(PathBuf, u32, i64)>,
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
    /// failure.
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
        for (path, mode, mtime) in self.deferred_dirs.into_iter().rev() {
            apply_metadata(
                &path,
                mode,
                mtime,
                self.opts.preserve_permissions,
                self.opts.preserve_mtime,
            )?;
        }
        Ok(())
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

#[allow(clippy::too_many_lines)]
pub(super) fn unpack_entry<R: Read>(
    entry: &mut Entry<R>,
    root: &Path,
    opts: &mut UnpackOptions,
    deferred_dirs: &mut Vec<(PathBuf, u32, i64)>,
) -> Result<UnpackSummary> {
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
    let output = root.join(&relative);
    ensure_safe_parents(root, &relative)?;
    match entry.kind {
        EntryType::Directory => {
            if output.exists() && fs::symlink_metadata(&output)?.file_type().is_symlink() {
                return Err(invalid("archive directory collides with symlink"));
            }
            fs::create_dir_all(&output)?;
            deferred_dirs.push((output, entry.header.mode, entry.header.mtime));
            summary.dirs = 1;
        }
        EntryType::File => {
            if !prepare_output(&output, opts.overwrite)? {
                summary.skipped.push(SkippedEntry {
                    path: original,
                    reason: SkipReason::Exists,
                });
                return Ok(summary);
            }
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
            apply_metadata(
                &output,
                entry.header.mode,
                entry.header.mtime,
                opts.preserve_permissions,
                opts.preserve_mtime,
            )?;
            summary.files = 1;
        }
        EntryType::Symlink => {
            if !prepare_output(&output, opts.overwrite)? {
                summary.skipped.push(SkippedEntry {
                    path: original,
                    reason: SkipReason::Exists,
                });
                return Ok(summary);
            }
            let target = entry
                .header
                .link_name()
                .ok_or_else(|| invalid("symlink lacks target"))?;
            match create_symlink(&target, &output) {
                Ok(()) => summary.symlinks = 1,
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
                return Ok(summary);
            }
            let target = entry
                .header
                .link_name()
                .ok_or_else(|| invalid("hardlink lacks target"))?;
            let target_relative = secure_relative_path(&target, opts.strip_components)?
                .ok_or_else(|| invalid("hardlink target was stripped away"))?;
            ensure_safe_parents(root, &target_relative)?;
            let source = root.join(target_relative);
            let metadata = fs::symlink_metadata(&source)
                .map_err(|_| invalid("hardlink target does not exist within destination"))?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("hardlink target may not be a symlink"));
            }
            fs::hard_link(source, output)?;
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
