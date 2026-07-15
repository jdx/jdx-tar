# jdx-tar

[![Crates.io](https://img.shields.io/crates/v/jdx-tar.svg)](https://crates.io/crates/jdx-tar)
[![Documentation](https://docs.rs/jdx-tar/badge.svg)](https://docs.rs/jdx-tar)
[![CI](https://github.com/jdx/jdx-tar/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/jdx-tar/actions/workflows/ci.yml)

Secure, synchronous, streaming tar **extraction** with complete GNU sparse
support — including the PAX sparse formats that no other pure-Rust tar crate
can extract.

```rust
use jdx_tar::{Archive, UnpackOptions};
use std::fs::File;

let archive = File::open("release.tar")?;
let summary = Archive::new(archive).unpack("output", &mut UnpackOptions::default())?;
println!("extracted {} files", summary.files);
# Ok::<(), std::io::Error>(())
```

Input only needs to implement `Read`, so decompression stays with the caller —
wrap the file in your favorite gzip/xz/zstd decoder first.

## Why another tar crate?

Because release tarballs in the wild contain things the existing Rust
ecosystem cannot extract, and tools kept papering over that by shelling out to
a system `tar` — which is its own portability roulette.

The concrete gap is **GNU sparse files in PAX format** (`GNU.sparse.*`
extended headers, formats 0.0, 0.1, and 1.0). This is what modern GNU tar
writes with `--sparse`, and it shows up in real release artifacts — for
example projects shipping disk images, where a multi-gigabyte sparse file
compresses to a few megabytes. Before this crate, a pure-Rust consumer
hitting one of those archives had two options: extract a garbage
`GNUSparseFile.0/<name>` file containing the raw sparse map, or spawn a
subprocess and hope the right `tar` is on `PATH` (GNU tar itself fails on
some of these archives with `Unexpected EOF`; only bsdtar/libarchive is
reliable).

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

None of this is a knock on tar-rs — it is a fine general-purpose library and
this crate's header parsing draws from it (see acknowledgements). jdx-tar
exists to own a narrower problem completely: **extracting real-world release
tarballs, correctly and safely, with good UX hooks**. If you need to *create*
archives or want an async API, use one of the crates above.

## Features

- **All four GNU sparse representations**: old GNU (type `S`, including
  extended headers) and PAX 0.0, 0.1, and 1.0. Sparse semantics follow Go's
  `archive/tar` and the GNU tar manual. Extraction creates real filesystem
  holes (`seek` + `set_len`), so a 20 GiB-logical disk image lands on disk at
  its actual data size.
- **Logical entry model**: an `Entry` always reads as its logical contents
  (holes return zeroes), with the data-extent map exposed via `sparse_map()`
  for hole-aware writers. Sparse names are un-mangled — you see the real path,
  never `GNUSparseFile.0/...`.
- **Extraction options that compose correctly**: `strip_components` at any
  depth, applied *after* long-name/PAX/sparse-name resolution;
  `preserve_mtime`, `preserve_permissions`, `overwrite`.
- **Progress and entry callbacks**: `on_progress` reports cumulative raw bytes
  consumed from the input reader; `on_entry` fires before each logical entry
  with its path, type, size, and sparseness.
- **Extraction summaries**: `unpack` returns an `UnpackSummary` with counts of
  files, directories, links, and sparse files, plus every skipped entry with a
  typed `SkipReason` — nothing is silently dropped.
- **Small and strict**: one dependency (`filetime`), `unsafe_code = "forbid"`,
  fuzzed with `cargo-fuzz`.

## Security posture

Extraction is secure by default and **has no insecure mode**. The following
are rejected: absolute paths, parent-directory traversal, writes through
previously extracted symlinks, invalid header checksums, oversized PAX
records, excessive sparse maps, and inconsistent or orphaned sparse metadata
(e.g. `GNU.sparse.name` path-aliasing). Link *targets* may point outside the
destination, but archive entries are never *written* outside it.

As with every path-based extraction API, callers should ensure no untrusted
local process can concurrently modify the destination tree during extraction.

## Progress bars

`on_progress` reports bytes consumed from the crate's input — the
*decompressed* stream. That is a good activity signal, but for a bounded
progress bar with an ETA you usually don't know the decompressed size up
front. The recommended pattern is to meter your *compressed* source instead:
wrap the `File` in a small counting reader **before** the decompression
decoder, and use the archive's on-disk size as the bar's total. Because
extraction streams — the unpacker pulls from the decoder, which pulls from the
file — compressed-bytes-consumed is a monotonic, accurate measure of overall
extraction progress. Use `on_entry` for "extracting `bin/tool`…" style status
messages.

## Non-goals

- **Writing archives** — extraction only.
- **Compression codecs** — hand this crate a decompressed `Read`.
- **Async** — wrap it in `spawn_blocking` if you need to.
- **Non-tar formats** — no zip, no 7z.

## Minimum supported Rust version

Rust 1.85 (edition 2024).

## Acknowledgements

Header layout and parsing details draw from the MIT/Apache-2.0 licensed
[`tar`](https://crates.io/crates/tar) crate. Sparse-format semantics follow
Go's `archive/tar` implementation and the GNU tar manual's *Storing Sparse
Files* appendix. The PAX sparse metadata hardening checks were informed by the
security work in
[`astral-tokio-tar`](https://github.com/astral-sh/tokio-tar).

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
