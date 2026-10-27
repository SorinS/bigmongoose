#!/bin/sh
# Makes test/vectors/xcrypto.txt with Go's golang.org/x/crypto (tools/govectors),
# offline from the module cache. With --check, compares with the file instead:
# every line but the bcrypt hashes, whose salts are random, must be the same.
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/test/vectors/xcrypto.txt
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$root/tools/govectors" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go run . > "$tmp/new")
if [ "$1" = "--check" ]; then
    grep -v '^bcrypt ' "$out" > "$tmp/a"
    grep -v '^bcrypt ' "$tmp/new" > "$tmp/b"
    if ! diff "$tmp/a" "$tmp/b"; then echo "xcrypto.txt differs from Go's" >&2; exit 1; fi
    echo "xcrypto.txt matches Go's ($(wc -l < "$tmp/new" | tr -d ' ') lines)"
else
    cp "$tmp/new" "$out"
    echo "wrote $out"
fi
