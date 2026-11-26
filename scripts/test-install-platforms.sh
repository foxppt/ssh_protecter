#!/usr/bin/env bash
set -euo pipefail
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/ssh-protecter-platform-test.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
for available in sshd.service ssh.service none; do
  (
    systemctl() { [[ "$1" = cat && "$2" = "$available" ]]; }
    set -- --root "$work/staging"
    source "$bundle/scripts/lib-install.sh"
    if [[ "$available" = none ]]; then
      if detect_ssh_unit >/dev/null 2>&1; then echo 'Unknown SSH layout accepted'; exit 1; fi
    else
      [[ $(detect_ssh_unit) = "$available" ]]
    fi
  )
done
echo 'PASS: Rocky/Ubuntu OpenSSH service detection and missing-service rejection.'
