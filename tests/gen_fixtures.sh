#!/usr/bin/env bash
set -euo pipefail
export COPYFILE_DISABLE=1
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1

# Regenerates the local fixture corpus. GNU tar is called `gtar` on macOS.
# The generated archives are checked in so all CI platforms test identical
# bytes. This script records how they were produced.
root="$(cd "$(dirname "$0")" && pwd)"
out="$root/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
rm -f "$out"/*.tar "$out"/*.tar.gz
bash "$root/create_fixture_tree.sh" "$work/input"

if [[ "$(uname -s)" == Darwin ]] && command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$root/create_fixture_tree.sh:/create_fixture_tree.sh:ro" \
    -v "$out:/out" ubuntu:24.04 bash -c '
    set -euo pipefail
    bash /create_fixture_tree.sh /tmp/input
    tar -C /tmp/input --sparse --hole-detection=raw --format=gnu --mtime=@1700000000 \
      --owner=0 --group=0 --numeric-owner -cf /out/gnu-old.tar .
    for version in 0.0 0.1 1.0; do
      tar -C /tmp/input --sparse --hole-detection=raw --format=pax \
        --sparse-version="$version" --pax-option=delete=atime,delete=ctime \
        --mtime=@1700000000 --owner=0 --group=0 \
        --numeric-owner -cf "/out/gnu-pax-$version.tar" .
    done
  '
elif command -v gtar >/dev/null 2>&1; then
  gtar -C "$work/input" --sparse --hole-detection=raw --format=gnu --mtime=@1700000000 \
    --owner=0 --group=0 --numeric-owner -cf "$out/gnu-old.tar" .
  for version in 0.0 0.1 1.0; do
    gtar -C "$work/input" --sparse --hole-detection=raw --format=pax \
      --sparse-version="$version" --pax-option=delete=atime,delete=ctime \
      --mtime=@1700000000 \
      --owner=0 --group=0 --numeric-owner \
      -cf "$out/gnu-pax-$version.tar" .
  done
elif tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar -C "$work/input" --sparse --hole-detection=raw --format=gnu --mtime=@1700000000 \
    --owner=0 --group=0 --numeric-owner -cf "$out/gnu-old.tar" .
  for version in 0.0 0.1 1.0; do
    tar -C "$work/input" --sparse --hole-detection=raw --format=pax \
      --sparse-version="$version" --pax-option=delete=atime,delete=ctime \
      --mtime=@1700000000 \
      --owner=0 --group=0 --numeric-owner \
      -cf "$out/gnu-pax-$version.tar" .
  done
else
  printf 'warning: GNU tar not found; skipping GNU sparse fixtures\n' >&2
fi

if command -v bsdtar >/dev/null 2>&1; then
  bsdtar -C "$work/input" --format pax --no-xattrs --no-acls --no-fflags \
    --uid 0 --gid 0 \
    --uname root --gname root -cf "$out/bsdtar-pax.tar" .
fi

# Compression is fixture storage only. The crate still receives a plain `Read`
# after tests wrap these bytes in a decoder.
for archive in "$out"/*.tar; do
  gzip -n -9 "$archive"
done
