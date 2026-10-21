#!/usr/bin/env bash
# Builds release packages for all supported targets.
#
#   scripts/build-release.sh <version> [outdir]
#
# Writes msstnetRelay31x_<version>_<os>_<arch>.tar.gz (.zip for Windows),
# each containing the binary, LICENSE, THIRD_PARTY_NOTICES and README.md,
# plus SHA256SUMS. Binaries are static (CGO_ENABLED=0) and built with
# -trimpath; archive timestamps come from the last commit, so the same
# commit and Go version give the same archives.
set -euo pipefail

version=${1:?usage: $0 <version> [outdir]}
out=${2:-dist}
name=msstnetRelay31x
targets="linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"

if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "version must look like v1.2.3 or v1.2.3-rc.1, got: $version" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
epoch=$(git log -1 --format=%ct)
rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in $targets; do
  goos=${target%/*}
  goarch=${target#*/}
  pkg=${name}_${version}_${goos}_${goarch}
  dir=$work/$pkg
  mkdir -p "$dir"
  ext=""
  [[ $goos == windows ]] && ext=".exe"
  echo "building $pkg"
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=$version" -o "$dir/$name$ext" .
  cp LICENSE THIRD_PARTY_NOTICES README.md "$dir/"
  find "$dir" -exec touch -h -d "@$epoch" {} +
  if [[ $goos == windows ]]; then
    (cd "$work" && find "$pkg" | LC_ALL=C sort | zip -X -q "$out/$pkg.zip" -@)
  else
    tar -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
      -cf - "$pkg" | gzip -n -9 > "$out/$pkg.tar.gz"
  fi
done

(cd "$out" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
cat "$out/SHA256SUMS"
