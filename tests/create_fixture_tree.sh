#!/usr/bin/env bash
set -euo pipefail

dest="$1"
mkdir -p "$dest/deep"

printf 'plain\n' >"$dest/plain.txt"
printf 'unicode\n' >"$dest/deep/δ.txt"
long="$(printf 'long-name-%.0s' {1..14})"
printf 'long\n' >"$dest/$long"
ln -s plain.txt "$dest/plain-link"
ln "$dest/plain.txt" "$dest/plain-hardlink"
ln -s "$long" "$dest/long-link"

# Data at offset zero and in the middle, with a hole extending to EOF.
truncate -s 16777216 "$dest/sparse-hole-at-eof.bin"
printf 'BEGIN' | dd of="$dest/sparse-hole-at-eof.bin" bs=1 seek=0 conv=notrunc 2>/dev/null
printf 'MIDDLE' | dd of="$dest/sparse-hole-at-eof.bin" bs=1 seek=4194304 conv=notrunc 2>/dev/null

# A final data extent ending exactly at the logical EOF.
truncate -s 16777216 "$dest/sparse-data-at-eof.bin"
printf 'END' | dd of="$dest/sparse-data-at-eof.bin" bs=1 seek=16777213 conv=notrunc 2>/dev/null

# No data extents at all.
truncate -s 8388608 "$dest/fully-sparse.bin"

# Keep archive metadata stable across hosts and regeneration runs.
find "$dest" -exec touch -h -t 202311142213.20 {} +
