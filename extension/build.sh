#!/usr/bin/env bash
# Package the AX Filter extension into a distributable zip for the Chrome Web
# Store (or for force-install hosting). Pure shell + zip, no network access.
#
#   usage: bash build.sh
#   output: dist/axfilter-extension-<version>.zip  (version read from manifest.json)
#
# Excluded from the package: test/, node_modules/, .git/, dist/, this script,
# ENTERPRISE.md, and any stray *.zip — only the files the browser actually
# loads are shipped.
set -euo pipefail

# Always operate from the extension directory, wherever the script is invoked.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f manifest.json ]; then
  echo "error: manifest.json not found in $(pwd)" >&2
  exit 1
fi

# Read "version" from manifest.json without needing jq (pure shell parsing).
VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json | head -n1)
if [ -z "${VERSION}" ]; then
  echo "error: could not read version from manifest.json" >&2
  exit 1
fi

OUT_DIR="dist"
OUT="${OUT_DIR}/axfilter-extension-${VERSION}.zip"

mkdir -p "${OUT_DIR}"
rm -f "${OUT}"

# -r recurse, -X strip extra file attributes for a reproducible archive.
zip -r -X "${OUT}" . \
  -x 'test/*' 'test' \
  -x 'node_modules/*' 'node_modules' \
  -x '.git/*' '.git' \
  -x 'dist/*' 'dist' \
  -x '*.zip' \
  -x 'build.sh' \
  -x 'ENTERPRISE.md' \
  -x '.DS_Store' '*/.DS_Store' \
  -x '*.map' \
  > /dev/null

echo "built: ${OUT}"
echo "contents:"
unzip -l "${OUT}"
