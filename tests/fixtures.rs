#![cfg(unix)]

use flate2::read::GzDecoder;
use jdx_tar::{Archive, UnpackOptions, UnpackSummary};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const GNU_FIXTURES: &[&str] = &[
    "gnu-old.tar.gz",
    "gnu-pax-0.0.tar.gz",
    "gnu-pax-0.1.tar.gz",
    "gnu-pax-1.0.tar.gz",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn unpack_jdx(name: &str, output: &Path) -> io::Result<UnpackSummary> {
    let decoder = GzDecoder::new(File::open(fixture(name))?);
    Archive::new(decoder).unpack(output, &mut UnpackOptions::default())
}

fn supports_sparse_files(directory: &Path) -> io::Result<bool> {
    let probe = directory.join("sparse-support-probe");
    let mut file = File::create(&probe)?;
    file.set_len(16 * 1024 * 1024)?;
    file.write_all(b"BEGIN")?;
    file.seek(SeekFrom::Start(4 * 1024 * 1024))?;
    file.write_all(b"MIDDLE")?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let supported = metadata.blocks() * 512 < metadata.len() / 8;
    drop(file);
    fs::remove_file(probe)?;
    Ok(supported)
}

fn collect_tree(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    fn visit(root: &Path, directory: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> {
        for item in fs::read_dir(directory)? {
            let path = item?.path();
            paths.insert(path.strip_prefix(root).unwrap().to_path_buf());
            if fs::symlink_metadata(&path)?.is_dir() {
                visit(root, &path, paths)?;
            }
        }
        Ok(())
    }

    let mut paths = BTreeSet::new();
    visit(root, root, &mut paths)?;
    Ok(paths)
}

fn assert_files_equal(left: &Path, right: &Path) -> io::Result<()> {
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut left_buf = vec![0_u8; 64 * 1024];
    let mut right_buf = vec![0_u8; 64 * 1024];
    loop {
        let left_len = left.read(&mut left_buf)?;
        let right_len = right.read(&mut right_buf)?;
        assert_eq!(left_len, right_len, "file lengths diverged while comparing");
        assert_eq!(&left_buf[..left_len], &right_buf[..right_len]);
        if left_len == 0 {
            return Ok(());
        }
    }
}

fn assert_trees_equal(left: &Path, right: &Path) -> io::Result<()> {
    let left_paths = collect_tree(left)?;
    let right_paths = collect_tree(right)?;
    assert_eq!(left_paths, right_paths);
    for relative in left_paths {
        let left_path = left.join(&relative);
        let right_path = right.join(&relative);
        let left_meta = fs::symlink_metadata(&left_path)?;
        let right_meta = fs::symlink_metadata(&right_path)?;
        assert_eq!(
            left_meta.file_type(),
            right_meta.file_type(),
            "type mismatch at {}",
            relative.display()
        );
        assert_eq!(
            left_meta.len(),
            right_meta.len(),
            "size mismatch at {}",
            relative.display()
        );
        if left_meta.file_type().is_symlink() {
            assert_eq!(fs::read_link(left_path)?, fs::read_link(right_path)?);
        } else if left_meta.is_file() {
            assert_files_equal(&left_path, &right_path)?;
        }
    }
    Ok(())
}

#[test]
fn extracts_real_gnu_sparse_fixtures() {
    for name in GNU_FIXTURES {
        let decoder = GzDecoder::new(File::open(fixture(name)).unwrap());
        let mut archive = Archive::new(decoder);
        let sparse_paths = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.sparse_map().is_some())
            .map(|entry| entry.path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            sparse_paths.len(),
            3,
            "wrong sparse maps for {name}: {sparse_paths:?}"
        );
        let output = tempfile::tempdir().unwrap();
        let summary = unpack_jdx(name, output.path()).unwrap_or_else(|error| {
            panic!("failed to extract {name}: {error}");
        });
        assert_eq!(summary.sparse_files, 3, "wrong sparse count for {name}");
        assert_eq!(
            fs::metadata(output.path().join("sparse-hole-at-eof.bin"))
                .unwrap()
                .len(),
            16 * 1024 * 1024
        );
        assert_eq!(
            fs::metadata(output.path().join("sparse-data-at-eof.bin"))
                .unwrap()
                .len(),
            16 * 1024 * 1024
        );
        assert_eq!(
            fs::metadata(output.path().join("fully-sparse.bin"))
                .unwrap()
                .len(),
            8 * 1024 * 1024
        );
        assert_eq!(
            fs::read(output.path().join("plain.txt")).unwrap(),
            b"plain\n"
        );
        assert_eq!(
            fs::read(output.path().join("deep/δ.txt")).unwrap(),
            b"unicode\n"
        );

        if supports_sparse_files(output.path()).unwrap() {
            let sparse = fs::metadata(output.path().join("sparse-hole-at-eof.bin")).unwrap();
            assert!(
                sparse.blocks() * 512 < sparse.len() / 8,
                "{name} was not written sparsely: {} blocks for {} bytes",
                sparse.blocks(),
                sparse.len()
            );
        }
    }
}

#[test]
fn matches_bsdtar_logical_output() {
    if Command::new("bsdtar").arg("--version").output().is_err() {
        eprintln!("bsdtar unavailable; skipping differential test");
        return;
    }
    let fixtures = GNU_FIXTURES.iter().copied().chain(["bsdtar-pax.tar.gz"]);
    for name in fixtures {
        let jdx_output = tempfile::tempdir().unwrap();
        let bsd_output = tempfile::tempdir().unwrap();
        unpack_jdx(name, jdx_output.path()).unwrap_or_else(|error| {
            panic!("failed to extract {name}: {error}");
        });
        let status = Command::new("bsdtar")
            .args([OsString::from("-xf"), fixture(name).into_os_string()])
            .arg("-C")
            .arg(bsd_output.path())
            .status()
            .unwrap();
        assert!(status.success(), "bsdtar failed to extract {name}");
        assert_trees_equal(jdx_output.path(), bsd_output.path()).unwrap();
    }
}
