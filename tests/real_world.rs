#![cfg(target_os = "linux")]

use flate2::read::GzDecoder;
use jdx_tar::{Archive, UnpackOptions};
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::process::Command;

const URL: &str = "https://github.com/smol-machines/smolvm/releases/download/v1.6.3/smolvm-1.6.3-darwin-arm64.tar.gz";
const IMAGE: &str = "smolvm-1.6.3-darwin-arm64/storage-template.ext4";
const OVERLAY: &str = "smolvm-1.6.3-darwin-arm64/overlay-template.ext4";

#[test]
#[ignore = "downloads a 31 MiB release archive"]
fn extracts_smolvm_goreleaser_sparse_archive() {
    let workspace = tempfile::tempdir().unwrap();
    let archive_path = workspace.path().join("smolvm.tar.gz");
    let output = workspace.path().join("output");
    let status = Command::new("curl")
        .args(["-fL", "--retry", "2", "-o"])
        .arg(&archive_path)
        .arg(URL)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "failed to download smolvm regression archive"
    );

    let decoder = GzDecoder::new(File::open(archive_path).unwrap());
    let summary = Archive::new(decoder)
        .unpack(&output, &mut UnpackOptions::default())
        .unwrap();
    assert_eq!(summary.sparse_files, 2);
    let metadata = fs::metadata(output.join(IMAGE)).unwrap();
    assert_eq!(metadata.len(), 20 * 1024 * 1024 * 1024);
    assert!(metadata.blocks() * 512 < metadata.len() / 8);
    let metadata = fs::metadata(output.join(OVERLAY)).unwrap();
    assert_eq!(metadata.len(), 10 * 1024 * 1024 * 1024);
    assert!(metadata.blocks() * 512 < metadata.len() / 8);
}
