use jdx_tar::{Archive, EntryUnpacker, SparseSegment, UnpackOptions};
#[cfg(unix)]
use jdx_tar::{EntryType, SkipReason};
#[cfg(unix)]
use std::cell::RefCell;
use std::io::{Cursor, Read};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::rc::Rc;

fn octal(field: &mut [u8], value: u64) {
    field.fill(0);
    let text = format!("{:0width$o}", value, width = field.len() - 1);
    field[..text.len()].copy_from_slice(text.as_bytes());
}

fn header(name: &str, size: u64, kind: u8) -> [u8; 512] {
    let mut block = [0_u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut block[100..108], 0o644);
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], 1_700_000_000);
    block[148..156].fill(b' ');
    block[156] = kind;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    let sum = format!("{checksum:06o}\0 ");
    block[148..156].copy_from_slice(sum.as_bytes());
    block
}

fn finish_header(block: &mut [u8; 512]) {
    block[148..156].fill(b' ');
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    let sum = format!("{checksum:06o}\0 ");
    block[148..156].copy_from_slice(sum.as_bytes());
}

#[cfg(unix)]
fn link_header(name: &str, target: &str, kind: u8) -> [u8; 512] {
    let mut block = header(name, 0, kind);
    block[157..157 + target.len()].copy_from_slice(target.as_bytes());
    finish_header(&mut block);
    block
}

#[allow(clippy::large_types_passed_by_value)]
fn append_entry(tar: &mut Vec<u8>, block: [u8; 512], data: &[u8]) {
    tar.extend_from_slice(&block);
    tar.extend_from_slice(data);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
}

fn pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    let mut length = body.len() + 1;
    loop {
        let record = format!("{length}{body}");
        if record.len() == length {
            return record;
        }
        length = record.len();
    }
}

fn pax_header(records: &[(&str, &str)]) -> (Vec<u8>, [u8; 512]) {
    let data = records
        .iter()
        .map(|(key, value)| pax_record(key, value))
        .collect::<String>()
        .into_bytes();
    let block = header("PaxHeaders/test", data.len() as u64, b'x');
    (data, block)
}

fn terminate(tar: &mut Vec<u8>) {
    tar.resize(tar.len() + 1024, 0);
}

#[test]
fn reads_dense_and_pax_path() {
    let mut tar = Vec::new();
    let (pax, pax_block) = pax_header(&[("path", "deep/δ/file.txt")]);
    append_entry(&mut tar, pax_block, &pax);
    append_entry(&mut tar, header("ignored", 5, b'0'), b"hello");
    terminate(&mut tar);

    let mut archive = Archive::new(Cursor::new(tar));
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_string_lossy(), "deep/δ/file.txt");
    let mut body = String::new();
    entry.read_to_string(&mut body).unwrap();
    assert_eq!(body, "hello");
    assert!(entries.next().is_none());
}

#[test]
fn securely_unpacks_selected_entries() {
    let mut tar = Vec::new();
    append_entry(&mut tar, header("root/whiteout", 3, b'0'), b"old");
    append_entry(&mut tar, header("root/tool", 5, b'0'), b"hello");
    terminate(&mut tar);

    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::new(Cursor::new(tar));
    let mut entries = archive.entries().unwrap();

    let skipped = entries.next().unwrap().unwrap();
    assert_eq!(
        skipped.path().unwrap().as_ref(),
        std::path::Path::new("root/whiteout")
    );

    let mut tool = entries.next().unwrap().unwrap();
    let mut options = UnpackOptions::default();
    options.strip_components = 1;
    let mut unpacker = EntryUnpacker::new(temp.path(), &mut options).unwrap();
    let summary = unpacker.unpack(&mut tool).unwrap();
    unpacker.finish().unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(std::fs::read(temp.path().join("tool")).unwrap(), b"hello");
    assert!(!temp.path().join("whiteout").exists());
}

#[test]
fn entry_unpack_handles_sparse_data_and_rejects_traversal() {
    let mut sparse = Vec::new();
    let (pax, pax_block) = pax_header(&[
        ("GNU.sparse.major", "0"),
        ("GNU.sparse.minor", "1"),
        ("GNU.sparse.size", "12"),
        ("GNU.sparse.map", "1,2,9,1"),
    ]);
    append_entry(&mut sparse, pax_block, &pax);
    append_entry(&mut sparse, header("root/sparse", 3, b'0'), b"abc");
    terminate(&mut sparse);

    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::new(Cursor::new(sparse));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut options = UnpackOptions::default();
    let mut unpacker = EntryUnpacker::new(temp.path(), &mut options).unwrap();
    let summary = unpacker.unpack(&mut entry).unwrap();
    unpacker.finish().unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(summary.sparse_files, 1);
    assert_eq!(
        std::fs::read(temp.path().join("root/sparse")).unwrap(),
        b"\0ab\0\0\0\0\0\0c\0\0"
    );

    let mut traversal = Vec::new();
    append_entry(&mut traversal, header("../outside", 1, b'0'), b"x");
    terminate(&mut traversal);
    let mut archive = Archive::new(Cursor::new(traversal));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut options = UnpackOptions::default();
    let mut unpacker = EntryUnpacker::new(temp.path(), &mut options).unwrap();
    assert!(unpacker.unpack(&mut entry).is_err());
}

#[cfg(unix)]
#[test]
fn entry_unpack_rejects_symlinked_parent() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), temp.path().join("link")).unwrap();

    let mut tar = Vec::new();
    append_entry(&mut tar, header("link/escape", 1, b'0'), b"x");
    terminate(&mut tar);
    let mut archive = Archive::new(Cursor::new(tar));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut options = UnpackOptions::default();
    let mut unpacker = EntryUnpacker::new(temp.path(), &mut options).unwrap();
    assert!(unpacker.unpack(&mut entry).is_err());
    assert!(!outside.path().join("escape").exists());
}

#[test]
fn entry_unpacker_defers_directory_metadata_until_finish() {
    let mut tar = Vec::new();
    append_entry(&mut tar, header("dir/", 0, b'5'), b"");
    append_entry(&mut tar, header("dir/file", 1, b'0'), b"x");
    terminate(&mut tar);

    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::new(Cursor::new(tar));
    let mut entries = archive.entries().unwrap();
    let mut options = UnpackOptions::default();
    let mut unpacker = EntryUnpacker::new(temp.path(), &mut options).unwrap();
    unpacker
        .unpack(&mut entries.next().unwrap().unwrap())
        .unwrap();
    unpacker
        .unpack(&mut entries.next().unwrap().unwrap())
        .unwrap();
    unpacker.finish().unwrap();

    let modified = std::fs::metadata(temp.path().join("dir"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(modified, 1_700_000_000);
}

#[test]
fn reads_pax_sparse_1_0_as_logical_content() {
    let mut tar = Vec::new();
    let (pax, pax_block) = pax_header(&[
        ("GNU.sparse.major", "1"),
        ("GNU.sparse.minor", "0"),
        ("GNU.sparse.name", "root/sparse.bin"),
        ("GNU.sparse.realsize", "20"),
        // Go's archive/tar writes the logical size here while retaining the
        // packed size in the following tar header.
        ("size", "20"),
    ]);
    append_entry(&mut tar, pax_block, &pax);
    let map = b"2\n2\n3\n15\n2\n";
    let mut physical = map.to_vec();
    physical.resize(512, 0);
    physical.extend_from_slice(b"abcXY");
    append_entry(
        &mut tar,
        header("GNUSparseFile.1/sparse.bin", physical.len() as u64, b'0'),
        &physical,
    );
    terminate(&mut tar);

    let mut archive = Archive::new(Cursor::new(tar));
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_string_lossy(), "root/sparse.bin");
    assert_eq!(entry.size(), 20);
    assert_eq!(
        entry.sparse_map().unwrap(),
        [
            SparseSegment { offset: 2, len: 3 },
            SparseSegment { offset: 15, len: 2 }
        ]
    );
    let mut body = Vec::new();
    entry.read_to_end(&mut body).unwrap();
    assert_eq!(&body[2..5], b"abc");
    assert_eq!(&body[15..17], b"XY");
    assert!(
        body[..2]
            .iter()
            .chain(&body[5..15])
            .chain(&body[17..])
            .all(|b| *b == 0)
    );
}

#[test]
fn reads_pax_sparse_0_0_and_0_1() {
    for records in [
        vec![
            ("GNU.sparse.major", "0"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.size", "12"),
            ("GNU.sparse.numblocks", "2"),
            ("GNU.sparse.offset", "1"),
            ("GNU.sparse.numbytes", "2"),
            ("GNU.sparse.offset", "9"),
            ("GNU.sparse.numbytes", "1"),
        ],
        vec![
            ("GNU.sparse.major", "0"),
            ("GNU.sparse.minor", "1"),
            ("GNU.sparse.size", "12"),
            ("GNU.sparse.map", "1,2,9,1"),
        ],
    ] {
        let mut tar = Vec::new();
        let (pax, pax_block) = pax_header(&records);
        append_entry(&mut tar, pax_block, &pax);
        append_entry(&mut tar, header("sparse", 3, b'0'), b"abc");
        terminate(&mut tar);
        let mut archive = Archive::new(Cursor::new(tar));
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        let mut body = Vec::new();
        entry.read_to_end(&mut body).unwrap();
        assert_eq!(body.len(), 12);
        assert_eq!(&body[1..3], b"ab");
        assert_eq!(body[9], b'c');
    }
}

#[test]
fn reads_old_gnu_sparse() {
    let mut tar = Vec::new();
    let mut block = header("old-sparse", 3, b'S');
    block[257..265].copy_from_slice(b"ustar  \0");
    octal(&mut block[386..398], 2);
    octal(&mut block[398..410], 2);
    octal(&mut block[410..422], 10);
    octal(&mut block[422..434], 1);
    octal(&mut block[483..495], 16);
    finish_header(&mut block);
    append_entry(&mut tar, block, b"abc");
    terminate(&mut tar);
    let mut archive = Archive::new(Cursor::new(tar));
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    let mut body = Vec::new();
    entry.read_to_end(&mut body).unwrap();
    assert_eq!(&body[2..4], b"ab");
    assert_eq!(body[10], b'c');
    assert_eq!(body.len(), 16);
}

#[test]
fn secure_unpack_strips_after_sparse_name_resolution() {
    let mut tar = Vec::new();
    let (pax, pax_block) = pax_header(&[
        ("GNU.sparse.major", "1"),
        ("GNU.sparse.minor", "0"),
        ("GNU.sparse.name", "one/two/file"),
        ("GNU.sparse.realsize", "4"),
    ]);
    append_entry(&mut tar, pax_block, &pax);
    let mut physical = b"0\n".to_vec();
    physical.resize(512, 0);
    append_entry(&mut tar, header("mangled", 512, b'0'), &physical);
    terminate(&mut tar);
    let temp = tempfile::tempdir().unwrap();
    let mut options = UnpackOptions::default();
    options.strip_components = 2;
    let summary = Archive::new(Cursor::new(tar))
        .unpack(temp.path(), &mut options)
        .unwrap();
    assert_eq!(summary.sparse_files, 1);
    assert_eq!(
        std::fs::metadata(temp.path().join("file")).unwrap().len(),
        4
    );
}

#[cfg(unix)]
#[test]
fn unpack_reports_callbacks_and_complete_summary() {
    let mut tar = Vec::new();
    append_entry(&mut tar, header("root/dir/", 0, b'5'), b"");
    let dense = vec![b'x'; 70 * 1024];
    append_entry(
        &mut tar,
        header("root/dir/dense", dense.len() as u64, b'0'),
        &dense,
    );

    let (pax, pax_block) = pax_header(&[
        ("GNU.sparse.major", "0"),
        ("GNU.sparse.minor", "1"),
        ("GNU.sparse.size", "12"),
        ("GNU.sparse.map", "1,2,9,1"),
    ]);
    append_entry(&mut tar, pax_block, &pax);
    append_entry(&mut tar, header("root/sparse", 3, b'0'), b"abc");
    append_entry(&mut tar, link_header("root/link", "dir/dense", b'2'), b"");
    append_entry(
        &mut tar,
        link_header("root/hard", "root/dir/dense", b'1'),
        b"",
    );
    append_entry(&mut tar, header("root/device", 0, b'3'), b"");
    append_entry(&mut tar, header("stripped", 0, b'0'), b"");
    terminate(&mut tar);
    let archive_len = tar.len() as u64;

    let progress = Rc::new(RefCell::new(Vec::new()));
    let entries = Rc::new(RefCell::new(Vec::new()));
    let mut options = UnpackOptions::default();
    options.strip_components = 1;
    options.on_progress = Some(Box::new({
        let progress = Rc::clone(&progress);
        move |update| progress.borrow_mut().push(update.bytes_read)
    }));
    options.on_entry = Some(Box::new({
        let entries = Rc::clone(&entries);
        move |entry| {
            entries.borrow_mut().push((
                entry.path.clone(),
                entry.entry_type,
                entry.size,
                entry.sparse,
            ));
        }
    }));

    let temp = tempfile::tempdir().unwrap();
    let summary = Archive::new(Cursor::new(tar))
        .unpack(temp.path(), &mut options)
        .unwrap();

    assert_eq!(summary.files, 2);
    assert_eq!(summary.dirs, 1);
    assert_eq!(summary.symlinks, 1);
    assert_eq!(summary.hardlinks, 1);
    assert_eq!(summary.sparse_files, 1);
    assert_eq!(
        summary
            .skipped
            .iter()
            .map(|entry| (&entry.path, &entry.reason))
            .collect::<Vec<_>>(),
        [
            (&PathBuf::from("root/device"), &SkipReason::UnsupportedType),
            (&PathBuf::from("stripped"), &SkipReason::Stripped),
        ]
    );

    let entries = entries.borrow();
    assert_eq!(entries.len(), 7);
    assert_eq!(
        entries[0],
        (PathBuf::from("root/dir"), EntryType::Directory, 0, false)
    );
    assert_eq!(entries[1].0, PathBuf::from("root/dir/dense"));
    assert_eq!(entries[1].2, dense.len() as u64);
    assert_eq!(
        entries[2],
        (PathBuf::from("root/sparse"), EntryType::File, 12, true)
    );
    assert_eq!(entries[6].0, PathBuf::from("stripped"));

    let progress = progress.borrow();
    assert!(!progress.is_empty());
    assert!(progress.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(progress.last(), Some(&archive_len));
    assert!(progress.iter().any(|bytes| *bytes >= 64 * 1024));
}

#[test]
fn rejects_traversal_checksum_and_symlink_escape() {
    let mut traversal = Vec::new();
    append_entry(&mut traversal, header("../outside", 1, b'0'), b"x");
    terminate(&mut traversal);
    let temp = tempfile::tempdir().unwrap();
    assert!(
        Archive::new(Cursor::new(traversal))
            .unpack(temp.path(), &mut UnpackOptions::default())
            .is_err()
    );

    let mut corrupt = header("file", 0, b'0').to_vec();
    corrupt[0] ^= 1;
    corrupt.resize(1536, 0);
    let mut archive = Archive::new(Cursor::new(corrupt));
    assert!(archive.entries().unwrap().next().unwrap().is_err());

    let mut links = Vec::new();
    let mut symlink = header("link", 0, b'2');
    symlink[157..160].copy_from_slice(b"../");
    finish_header(&mut symlink);
    append_entry(&mut links, symlink, b"");
    append_entry(&mut links, header("link/pwn", 1, b'0'), b"x");
    terminate(&mut links);
    assert!(
        Archive::new(Cursor::new(links))
            .unpack(temp.path(), &mut UnpackOptions::default())
            .is_err()
    );
}

#[test]
fn rejects_absolute_oversized_truncated_and_invalid_sparse_inputs() {
    let temp = tempfile::tempdir().unwrap();

    let mut absolute = Vec::new();
    append_entry(&mut absolute, header("/outside", 1, b'0'), b"x");
    terminate(&mut absolute);
    assert!(
        Archive::new(Cursor::new(absolute))
            .unpack(temp.path(), &mut UnpackOptions::default())
            .is_err()
    );

    let mut oversized_metadata = header("PaxHeaders/huge", 1024 * 1024 + 1, b'x').to_vec();
    oversized_metadata.resize(1536, 0);
    let mut archive = Archive::new(Cursor::new(oversized_metadata));
    assert!(archive.entries().unwrap().next().unwrap().is_err());

    let mut invalid_sparse = Vec::new();
    let (pax, pax_block) = pax_header(&[("GNU.sparse.size", "5"), ("GNU.sparse.map", "4,2")]);
    append_entry(&mut invalid_sparse, pax_block, &pax);
    append_entry(&mut invalid_sparse, header("sparse", 2, b'0'), b"xx");
    terminate(&mut invalid_sparse);
    let mut archive = Archive::new(Cursor::new(invalid_sparse));
    assert!(archive.entries().unwrap().next().unwrap().is_err());

    let mut orphaned_sparse_name = Vec::new();
    let (pax, pax_block) = pax_header(&[("GNU.sparse.name", "alias")]);
    append_entry(&mut orphaned_sparse_name, pax_block, &pax);
    append_entry(&mut orphaned_sparse_name, header("real", 0, b'0'), b"");
    terminate(&mut orphaned_sparse_name);
    let mut archive = Archive::new(Cursor::new(orphaned_sparse_name));
    assert!(archive.entries().unwrap().next().unwrap().is_err());

    let mut truncated = header("file", 5, b'0').to_vec();
    truncated.extend_from_slice(b"hi");
    let mut archive = Archive::new(Cursor::new(truncated));
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    let mut body = Vec::new();
    assert!(entry.read_to_end(&mut body).is_err());
}
