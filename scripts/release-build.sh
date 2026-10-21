#!/usr/bin/env bash
#
# Build the release archives for one version.
#
# Used by .github/workflows/release.yml and by "make release-snapshot".
# Produces, in <outdir>:
#   eimmortal_<version>_<os>_<arch>.tar.gz   (linux, darwin)
#   eimmortal_<version>_<os>_<arch>.zip      (windows)
#   checksums.txt
#
# Usage: scripts/release-build.sh <version> [outdir]
#   version may be given with or without a leading "v".

set -euo pipefail

version="${1:?usage: release-build.sh <version> [outdir]}"
out="${2:-dist}"
version="${version#v}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

targets=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

rm -rf -- "$out"
mkdir -p "$out"

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="eimmortal_${version}_${goos}_${goarch}"
  dir="${out}/${name}"
  bin="eimmortal"
  if [ "$goos" = "windows" ]; then
    bin="eimmortal.exe"
  fi

  echo "building ${name}"
  mkdir -p "$dir"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${version}" \
      -o "${dir}/${bin}" ./cmd/eimmortal

  cp README.md config.example.toml "$dir/"
  cp -R docs "$dir/"

  if [ "$goos" = "windows" ]; then
    (cd "$out" && zip -qr "${name}.zip" "${name}")
  else
    tar -C "$out" -czf "${out}/${name}.tar.gz" "${name}"
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd=(shasum -a 256)
else
  echo "error: need sha256sum or shasum to write checksums.txt" >&2
  exit 1
fi

(cd "$out" && "${hash_cmd[@]}" eimmortal_*.tar.gz eimmortal_*.zip > checksums.txt)
echo "wrote ${out}/checksums.txt"
