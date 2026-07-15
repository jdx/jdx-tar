# jdx-tar

`jdx-tar` is a synchronous, streaming, read/extract-focused tar library. It
supports ustar, GNU long names, PAX headers, old GNU sparse files, and GNU PAX
sparse formats 0.0, 0.1, and 1.0. Input only needs to implement `Read`, so
decompression remains the caller's responsibility.

```rust
use jdx_tar::{Archive, UnpackOptions};
use std::fs::File;

let archive = File::open("release.tar")?;
Archive::new(archive).unpack("output", &mut UnpackOptions::default())?;
# Ok::<(), std::io::Error>(())
```

## Security posture

Extraction is secure by default and has no insecure mode. Absolute paths,
parent traversal, writes through previously extracted symlinks, invalid header
checksums, oversized PAX records, excessive sparse maps, and inconsistent
sparse metadata are rejected. Link targets may be external, but archive entries
are never written outside the destination.

As with every path-based extraction API, callers should ensure no untrusted
local process can concurrently modify the destination tree during extraction.

## Format notes

Sparse entries read as their logical contents, with holes returned as zeroes.
The sparse map is also exposed so extraction can create real filesystem holes.
Progress reports raw bytes consumed from the tar stream.

The header layout and parsing details draw from the MIT/Apache-2.0 licensed
[`tar`](https://crates.io/crates/tar) crate. Sparse semantics follow Go's
`archive/tar` implementation and the GNU tar manual.

Licensed under MIT or Apache-2.0, at your option.

