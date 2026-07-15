# jdx-tar

[![Crates.io](https://img.shields.io/crates/v/jdx-tar.svg)](https://crates.io/crates/jdx-tar)
[![Documentation](https://docs.rs/jdx-tar/badge.svg)](https://docs.rs/jdx-tar)
[![CI](https://github.com/jdx/jdx-tar/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/jdx-tar/actions/workflows/ci.yml)

Synchronous, streaming tar extraction with support for all GNU sparse
formats, including the PAX sparse formats that other pure-Rust tar crates
cannot extract.

```rust
use jdx_tar::{Archive, UnpackOptions};
use std::fs::File;

let archive = File::open("release.tar")?;
let summary = Archive::new(archive).unpack("output", &mut UnpackOptions::default())?;
println!("extracted {} files", summary.files);
# Ok::<(), std::io::Error>(())
```

Input is anything that implements `Read`. Decompression is the caller's
responsibility: wrap the file in a gzip/xz/zstd decoder first.

## Why another tar crate?

[mise](https://github.com/jdx/mise) kept hitting release tarballs that no
Rust tar crate could extract, and papered over it by shelling out to a system
`tar`. That fallback was unreliable: which `tar` you get depends on the
platform and `PATH`, and GNU tar itself fails on some of these archives with
`Unexpected EOF` (only bsdtar handles them all). This crate exists to delete
that fallback.

The gap is GNU sparse files in PAX format (`GNU.sparse.*` extended headers,
formats 0.0, 0.1, and 1.0), which is what modern GNU tar writes with
`--sparse`. These appear in real release artifacts, typically disk images
where a multi-gigabyte sparse file compresses to a few megabytes. The `tar`
crate extracts these as a mangled `GNUSparseFile.0/<name>` file whose
contents are the raw sparse map and packed data.

|                                            | `jdx-tar` | [`tar`](https://crates.io/crates/tar) (tar-rs) | [`astral-tokio-tar`](https://crates.io/crates/astral-tokio-tar) | libarchive bindings | system `tar` subprocess |
| ------------------------------------------ | --------- | ---------------------------------------------- | ---------------------------------------------------------------- | ------------------- | ----------------------- |
| PAX GNU sparse extraction (0.0/0.1/1.0)    | ✅        | ❌                                             | ❌ (validates, doesn't expand)                                    | ✅                  | depends which `tar`     |
| Old GNU sparse (type `S`)                  | ✅        | ✅                                             | ✅                                                                | ✅                  | ✅                      |
| Sync `Read`-based streaming                | ✅        | ✅                                             | ❌ (async only)                                                   | ✅                  | n/a                     |
| `strip_components` built in (any depth)    | ✅        | ❌                                             | ❌                                                                | ❌                  | ✅                      |
| Progress + per-entry callbacks             | ✅        | ❌                                             | ❌                                                                | ❌                  | ❌                      |
| Secure extraction is the *only* mode       | ✅        | partial (unchecked `Entry::unpack` exists)     | ✅                                                                | ❌                  | ❌                      |
| Pure Rust, no C, `unsafe_code = "forbid"`  | ✅        | ✅                                             | ✅                                                                | ❌ (links C)        | n/a                     |
| Writes archives                            | ❌        | ✅                                             | ✅                                                                | ✅                  | ✅                      |

This crate's header parsing draws from the `tar` crate (see
acknowledgements); use that or `astral-tokio-tar` if you need archive
creation or an async API today. Archive writing is not implemented here yet,
and a well-tested PR adding synchronous, streaming tar writing would be
welcome.

## Features

- All four GNU sparse representations: old GNU (type `S`, including extended
  headers) and PAX 0.0, 0.1, and 1.0. Sparse semantics follow Go's
  `archive/tar` and the GNU tar manual.
- On Unix, sparse files are extracted with real filesystem holes, so a
  20 GiB-logical disk image occupies only its data size on disk. On Windows,
  extracted contents are identical but holes are not preserved, so sparse
  files take their full logical size.
- Entries read as their logical contents (holes read as zeroes), and the
  data-extent map is available via `sparse_map()`. Paths are fully resolved
  across long names, PAX overrides, and sparse name un-mangling, so you never
  see `GNUSparseFile.0/...`.
- Individual entries can be securely extracted with `Entry::unpack_in`, which
  lets callers inspect or skip entries while retaining the same path and
  symlink protections as whole-archive extraction.
- `strip_components` at any depth, applied after name resolution, plus
  `preserve_mtime`, `preserve_permissions`, and `overwrite`.
- `on_progress` and `on_entry` callbacks. `unpack` returns an `UnpackSummary`
  with counts and a typed `SkipReason` for every skipped entry.
- One dependency (`filetime`), `unsafe_code = "forbid"`, fuzzed with
  `cargo-fuzz`.

## Security

Extraction is secure by default and has no insecure mode. Rejected: absolute
paths, parent-directory traversal, writes through previously extracted
symlinks, invalid header checksums, oversized PAX records, excessive sparse
maps, and inconsistent or orphaned sparse metadata such as `GNU.sparse.name`
path-aliasing. Link targets may point outside the destination; archive
entries are never written outside it.

As with any path-based extraction API, callers should ensure no untrusted
local process can modify the destination tree during extraction.

## Progress bars

`on_progress` reports bytes consumed from the input reader, which is the
decompressed stream. Its total size usually isn't known up front, so it works
as an activity signal but not a bounded bar. For a real progress bar, count
bytes on the compressed file with a wrapping reader placed before the
decoder, and use the file's size as the total. Extraction is streaming, so
compressed bytes consumed track overall progress accurately. Use `on_entry`
for per-file status messages.

## Non-goals

- Compression codecs: pass a decompressed `Read`.
- Async: wrap calls in `spawn_blocking`.
- Other formats: no zip, no 7z.

## Minimum supported Rust version

Rust 1.85 (edition 2024).

## Acknowledgements

Header layout and parsing details draw from the MIT/Apache-2.0 licensed
[`tar`](https://crates.io/crates/tar) crate. Sparse-format semantics follow
Go's `archive/tar` implementation and the GNU tar manual's *Storing Sparse
Files* appendix. The PAX sparse metadata hardening checks were informed by
the security work in
[`astral-tokio-tar`](https://github.com/astral-sh/tokio-tar).

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
