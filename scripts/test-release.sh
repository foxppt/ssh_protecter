#!/usr/bin/env bash
set -euo pipefail
archive=$(realpath -- "${1:?release archive required}")
work=$(mktemp -d /tmp/ssh-protecter-release-test.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
tar -xzf "$archive" -C "$work"
cd -- "$work"
sha256sum --strict -c dist/SHA256SUMS >/dev/null
[[ $(dist/ssh-protecter-linux-amd64 version) = 0.1.0-rc2 ]]
bash scripts/test-installer.sh
echo 'PASS: release checksum manifest, Linux executable modes, version and staged installation.'
