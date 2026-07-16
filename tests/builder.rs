use jdx_tar::{Archive, Builder, EntryType, Header};
use std::io::{Cursor, Read};

#[test]
fn writes_streaming_archive_with_metadata_and_links() {
    let mut bytes = Vec::new();
    let target = format!("../{}", "deep/".repeat(30));
    {
        let mut builder = Builder::new(&mut bytes);

        let mut dir = Header::new_gnu(EntryType::Directory);
        dir.set_mode(0o755);
        builder
            .append_data(&mut dir, "pkg/", std::io::empty())
            .unwrap();

        let mut file = Header::new_gnu(EntryType::File);
        file.set_mode(0o755);
        file.set_uid(1000);
        file.set_gid(1001);
        file.set_mtime(42);
        file.set_size(5);
        builder
            .append_data(&mut file, "pkg/tool", &b"hello"[..])
            .unwrap();

        let mut link = Header::new_gnu(EntryType::Symlink);
        link.set_mode(0o777);
        builder.append_link(&mut link, "pkg/link", &target).unwrap();
        builder.finish().unwrap();
    }

    assert_eq!(bytes.len() % 512, 0);
    let mut archive = Archive::new(Cursor::new(bytes));
    let mut entries = archive.entries().unwrap();

    let dir = entries.next().unwrap().unwrap();
    assert_eq!(dir.path().unwrap().as_ref(), std::path::Path::new("pkg/"));
    assert_eq!(dir.entry_type(), EntryType::Directory);

    let mut file = entries.next().unwrap().unwrap();
    assert_eq!(
        file.path().unwrap().as_ref(),
        std::path::Path::new("pkg/tool")
    );
    assert_eq!(file.header().mode(), 0o755);
    assert_eq!(file.header().uid(), 1000);
    assert_eq!(file.header().gid(), 1001);
    assert_eq!(file.header().mtime(), 42);
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "hello");

    let link = entries.next().unwrap().unwrap();
    assert_eq!(link.entry_type(), EntryType::Symlink);
    assert_eq!(
        link.header().link_name().unwrap().as_ref(),
        std::path::Path::new(&target)
    );
    assert!(entries.next().is_none());
}

#[test]
fn writes_long_paths_and_rejects_short_data() {
    let long_path = format!("root/{}/tool", "nested/".repeat(20));
    let mut bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = Header::new_gnu(EntryType::File);
        header.set_size(1);
        builder
            .append_data(&mut header, &long_path, &b"x"[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let mut archive = Archive::new(Cursor::new(bytes));
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(
        entry.path().unwrap().as_ref(),
        std::path::Path::new(&long_path)
    );

    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu(EntryType::File);
    header.set_size(2);
    let error = builder
        .append_data(&mut header, "short", &b"x"[..])
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    let mut next = Header::new_gnu(EntryType::File);
    assert!(
        builder
            .append_data(&mut next, "next", std::io::empty())
            .is_err()
    );
    assert!(builder.finish().is_err());
}

#[test]
fn output_is_compatible_with_tar_rs() {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu(EntryType::File);
    header.set_size(7);
    builder
        .append_data(&mut header, "registry/tool.toml", &b"backend"[..])
        .unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(
        entry.path().unwrap().as_ref(),
        std::path::Path::new("registry/tool.toml")
    );
    let mut contents = String::new();
    entry.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "backend");
}

#[test]
fn invalid_link_does_not_write_partial_metadata() {
    let mut builder = Builder::new(Vec::new());
    let mut link = Header::new_gnu(EntryType::Symlink);
    let long_target = "target/".repeat(20);
    assert!(builder.append_link(&mut link, "", long_target).is_err());

    let mut file = Header::new_gnu(EntryType::File);
    file.set_size(2);
    builder.append_data(&mut file, "ok", &b"ok"[..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = Archive::new(Cursor::new(bytes));
    let mut entries = archive.entries().unwrap();
    assert_eq!(
        entries.next().unwrap().unwrap().path().unwrap().as_ref(),
        std::path::Path::new("ok")
    );
    assert!(entries.next().is_none());
}

#[test]
fn oversized_long_records_do_not_write_partial_metadata() {
    let oversized = "x".repeat(1024 * 1024);
    let mut builder = Builder::new(Vec::new());

    let mut file = Header::new_gnu(EntryType::File);
    let error = builder
        .append_data(&mut file, &oversized, std::io::empty())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut link = Header::new_gnu(EntryType::Symlink);
    let long_target = "t".repeat(101);
    let error = builder
        .append_link(&mut link, &oversized, &long_target)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut link = Header::new_gnu(EntryType::Symlink);
    let error = builder
        .append_link(&mut link, "oversized-target", &oversized)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut valid = Header::new_gnu(EntryType::File);
    valid.set_size(2);
    builder.append_data(&mut valid, "ok", &b"ok"[..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = Archive::new(Cursor::new(bytes));
    let mut entries = archive.entries().unwrap();
    assert_eq!(
        entries.next().unwrap().unwrap().path().unwrap().as_ref(),
        std::path::Path::new("ok")
    );
    assert!(entries.next().is_none());
}
