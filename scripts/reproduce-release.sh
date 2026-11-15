#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# Rebuild a release's two files from its tag, the way .github/workflows/release.yml builds them, and compare their
# SHA-256 with the release's SHA256SUMS:
#
#   scripts/reproduce-release.sh v0.1.18                  # fetches the release's SHA256SUMS with gh
#   scripts/reproduce-release.sh v0.1.18 path/SHA256SUMS  # or compares with a SHA256SUMS you already have
#
# Exit 0 only when both files were rebuilt and both digests match. It needs git, npm and, without a SHA256SUMS
# argument, gh. It runs no package script (npm pack --ignore-scripts) and writes only to a temporary folder it removes.
#
# The npm package depends on the files' permission bits (npm pack records them): build from a tree whose files are
# 644 and 755, as git checks them out under umask 022. This script sets that umask. Modification times do not matter;
# npm pack writes a fixed one.
set -euo pipefail

tag="${1:?usage: reproduce-release.sh vX.Y.Z [SHA256SUMS]}"
sums="${2:-}"
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a release tag: $tag" >&2; exit 2 ;; esac
version="${tag#v}"
git rev-parse -q --verify "refs/tags/$tag^{commit}" >/dev/null || { echo "no tag $tag in this clone (git fetch --tags)" >&2; exit 2; }

umask 022
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -z "$sums" ]; then
  gh release download "$tag" -p SHA256SUMS -D "$work/expected" -R "${WARDLATCH_REPO:-deimos-hq/wardlatch}"
  sums="$work/expected/SHA256SUMS"
fi
test -s "$sums" || { echo "SHA256SUMS is empty or missing: $sums" >&2; exit 1; }

src="wardlatch-$tag.tar.gz" pkg="wardlatch-$version.tgz"
# the release's SHA256SUMS must name exactly these two files, each once
names="$(awk '{print $2}' "$sums" | sort | tr '\n' ' ')"
want="$(printf '%s\n%s\n' "$src" "$pkg" | sort | tr '\n' ' ')"
[ "$names" = "$want" ] || { echo "SHA256SUMS names [${names% }], expected [${want% }]" >&2; exit 1; }

mkdir "$work/out" "$work/tree"
git archive --format=tar.gz --prefix="wardlatch-$tag/" -o "$work/out/$src" "$tag"
git archive "$tag" | tar -x -C "$work/tree"
(cd "$work/tree" && npm pack --silent --ignore-scripts --pack-destination "$work/out" >/dev/null)
test -s "$work/out/$pkg" || { echo "npm pack made no $pkg" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$work/out" && sha256 "$src" "$pkg")
cp "$sums" "$work/out/expected.sums"
if (cd "$work/out" && sha256 -c expected.sums); then
  echo "reproduced: $tag rebuilt from its tag matches its SHA256SUMS byte for byte"
else
  echo "NOT reproduced: $tag rebuilt from its tag differs from its SHA256SUMS" >&2
  exit 1
fi
