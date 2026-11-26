#!/usr/bin/env bash
# Prebuilt Linux test binaries; no Go toolchain or real SSH service changes.
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run as root on the Linux test host.' >&2; exit 1; }
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
skip_nft=0
if [[ ${1:-} = --skip-nft ]]; then skip_nft=1; shift; fi
if (($#)); then echo 'Usage: run-fault-tests.sh [--skip-nft]' >&2; exit 2; fi
tests="$bundle/dist/fault-tests"
for name in cli state service timeguard firewall totp; do
  [[ -f "$tests/$name.test" ]] || { echo "Missing test binary: $tests/$name.test" >&2; exit 1; }
  chmod 700 -- "$tests/$name.test"
  "$tests/$name.test" -test.v -test.timeout=90s
done
SSH_PROTECTER_SYSTEMD_TEST=1 "$tests/cli.test" -test.run=TestSystemdRecoversStoppedProcess -test.v -test.timeout=40s
SSH_PROTECTER_TMPFS_TEST=1 "$tests/state.test" -test.run=TestFilesystemENOSPC -test.v -test.timeout=30s
if ((!skip_nft)); then
 SSH_PROTECTER_NFT_TEST=1 "$tests/firewall.test" -test.run=TestKernelNamespace -test.v -test.timeout=30s
else
 echo 'SKIP: real nftables integration explicitly omitted; this is not full host acceptance.'
fi
bash "$bundle/scripts/test-installer.sh" "$bundle/dist/ssh-protecter-linux-amd64"
bash "$bundle/scripts/test-install-platforms.sh"
echo 'PASS: isolated fault tests completed; real reboot/SSH/Docker tests remain target-host acceptance.'
