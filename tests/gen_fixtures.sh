#!/usr/bin/env bash
set -euo pipefail

# Regenerates the local fixture corpus. GNU tar is called `gtar` on macOS.
# The generated directory is intentionally ignored because format tests build
# equivalent byte-level fixtures directly and remain hermetic on every target.
root="$(cd "$(dirname "$0")" && pwd)"
out="$root/fixtures/generated"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out" "$work/input/deep"

printf 'plain\n' >"$work/input/plain.txt"
printf 'unicode\n' >"$work/input/deep/δ.txt"
long="$(printf 'long-name-%.0s' {1..14})"
printf 'long\n' >"$work/input/$long"
ln -s plain.txt "$work/input/plain-link"
ln "$work/input/plain.txt" "$work/input/plain-hardlink"

# Data at the beginning, middle, and near EOF, with holes between and after.
dd if=/dev/zero of="$work/input/sparse.bin" bs=1 count=0 seek=16777216 2>/dev/null
printf 'BEGIN' | dd of="$work/input/sparse.bin" bs=1 seek=0 conv=notrunc 2>/dev/null
printf 'MIDDLE' | dd of="$work/input/sparse.bin" bs=1 seek=4194304 conv=notrunc 2>/dev/null
printf 'END' | dd of="$work/input/sparse.bin" bs=1 seek=12582912 conv=notrunc 2>/dev/null

if command -v gtar >/dev/null 2>&1; then
  gtar -C "$work/input" --sparse --format=gnu -cf "$out/gnu-old.tar" .
  for version in 0.0 0.1 1.0; do
    gtar -C "$work/input" --sparse --format=pax --sparse-version="$version" \
      -cf "$out/gnu-pax-$version.tar" .
  done
elif tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar -C "$work/input" --sparse --format=gnu -cf "$out/gnu-old.tar" .
  for version in 0.0 0.1 1.0; do
    tar -C "$work/input" --sparse --format=pax --sparse-version="$version" \
      -cf "$out/gnu-pax-$version.tar" .
  done
else
  printf 'warning: GNU tar not found; skipping GNU sparse fixtures\n' >&2
fi

if command -v bsdtar >/dev/null 2>&1; then
  bsdtar -C "$work/input" --format pax -cf "$out/bsdtar-pax.tar" .
fi

