#!/usr/bin/env bash
# Writes a version into the workspace before a release build:   scripts/set-version.sh 0.4.0
# Cargo.toml keeps the placeholder 0.0.0-dev in git; the release workflow and the AUR package
# run this with the version from the tag, and nothing they change is committed.
# For a release (no "-" in the version), the AppStream metainfo also gets a <release> entry if it
# has none: its description comes from $RELEASE_NOTES (the tag message: paragraphs, and "- "
# lines for a list), or stays empty.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?usage: set-version.sh VERSION}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "set-version.sh: $version is not a semantic version" >&2
  exit 1
fi
placeholder='version = "0.0.0-dev"'
grep -qx "$placeholder" Cargo.toml || { echo "set-version.sh: Cargo.toml has no $placeholder" >&2; exit 1; }
# The workspace members are the only packages at 0.0.0-dev, in Cargo.toml and Cargo.lock alike.
# (-i.orig: macOS's sed needs a suffix.)
sed -i.orig "s/^$placeholder\$/version = \"$version\"/" Cargo.toml Cargo.lock
rm Cargo.toml.orig Cargo.lock.orig

metainfo=packaging/linux/ch.giosuel.SomeDesk.metainfo.xml
if [[ "$version" == *-* ]] || grep -q "<release version=\"$version\"" "$metainfo"; then
  exit 0
fi
entry=$(printf '%s\n' "${RELEASE_NOTES:-}" | awk -v version="$version" -v date="$(date -u +%F)" '
  function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
  function close_block() {
    if (para != "") { body = body "        <p>" esc(para) "</p>\n"; para = "" }
    if (list) { body = body "        </ul>\n"; list = 0 }
  }
  { sub(/[ \t\r]+$/, "") }
  /^[-*] / {
    if (para != "") close_block()
    if (!list) { body = body "        <ul>\n"; list = 1 }
    body = body "          <li>" esc(substr($0, 3)) "</li>\n"
    next
  }
  /^$/ { close_block(); next }
  { if (list) close_block(); para = (para == "" ? $0 : para " " $0) }
  END {
    close_block()
    if (body == "") print "    <release version=\"" version "\" date=\"" date "\"/>"
    else printf "    <release version=\"%s\" date=\"%s\">\n      <description>\n%s      </description>\n    </release>\n", version, date, body
  }')
# The newest release goes first.
ENTRY="$entry" awk '{ print } /<releases>/ && !done { print ENVIRON["ENTRY"]; done = 1 }' "$metainfo" >"$metainfo.new"
mv "$metainfo.new" "$metainfo"
