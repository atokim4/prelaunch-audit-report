#!/bin/sh
# Downloads the PostgREST release the live-probe end-to-end test runs against, checks its sha256 and
# unpacks it to .cache/postgrest/. Linux x86-64 only (the static build); elsewhere set POSTGREST_BIN.
set -eu
VERSION=v16.5
SHA256=5099e7ada38f9f6846cd87c14c5f158b7c165f1e9959665ad412e61f4dceba95
DIR="$(cd "$(dirname "$0")/.." && pwd)/.cache/postgrest"
URL="https://github.com/PostgREST/postgrest/releases/download/$VERSION/postgrest-$VERSION-linux-static-x86-64.tar.xz"

if [ -x "$DIR/postgrest" ] && "$DIR/postgrest" --version | grep -q "${VERSION#v}"; then
  echo "PostgREST $VERSION already in $DIR"
  exit 0
fi
mkdir -p "$DIR"
curl -fsSL -o "$DIR/postgrest.tar.xz" "$URL"
echo "$SHA256  $DIR/postgrest.tar.xz" | sha256sum -c -
tar -xJf "$DIR/postgrest.tar.xz" -C "$DIR"
rm "$DIR/postgrest.tar.xz"
"$DIR/postgrest" --version
