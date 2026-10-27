#!/bin/sh
# Builds tools/govectors (Go's golang.org/x/crypto) offline from the module
# cache and runs it with these arguments; see tools/govectors/main.go.
#
#	tools/govectors.sh > test/vectors/xcrypto.txt   # the vectors
#	tools/govectors.sh --check                       # compared with xcrypto.txt instead
#
# With --check every line but the bcrypt hashes, whose salts are random,
# must be the same.
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
dir=$root/tools/govectors
bin=${TMPDIR:-/tmp}/govectors.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
[ "$1" = "--check" ] || exec "$bin" "$@"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$bin" > "$tmp/new"
grep -v '^bcrypt ' "$root/test/vectors/xcrypto.txt" > "$tmp/a"
grep -v '^bcrypt ' "$tmp/new" > "$tmp/b"
if ! diff "$tmp/a" "$tmp/b"; then echo "xcrypto.txt differs from Go's" >&2; exit 1; fi
echo "xcrypto.txt matches Go's ($(wc -l < "$tmp/new" | tr -d ' ') lines)"
