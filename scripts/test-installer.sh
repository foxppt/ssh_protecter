#!/usr/bin/env bash
set -euo pipefail
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/ssh-protecter-installer-test.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
target="$work/root"
binary=${1:-"$bundle/dist/ssh-protecter-linux-amd64"}
args=(--root "$target" --binary "$binary" --config "$bundle/configs/nginx.example.yaml")
bash "$bundle/scripts/install.sh" "${args[@]}" --dry-run
[[ ! -e "$target" ]] || { echo 'dry-run modified staging root'; exit 1; }
bash "$bundle/scripts/install.sh" "${args[@]}"
[[ -x "$target/usr/local/sbin/ssh-protecter" && -f "$target/var/lib/ssh-protecter/install.manifest" ]]
printf 'user configuration\n' > "$target/etc/ssh-protecter/config.yaml"
printf 'private identity\n' > "$target/etc/ssh-protecter/bootstrap.json"
printf 'persistent bans\n' > "$target/var/lib/ssh-protecter/state.db"
printf 'unrelated\n' > "$target/etc/systemd/system/unrelated.service"
bash "$bundle/scripts/install.sh" "${args[@]}"
grep -q 'user configuration' "$target/etc/ssh-protecter/config.yaml"
unit="$target/etc/systemd/system/ssh-protecter.service"
printf '# user modified\n' >> "$unit"
if bash "$bundle/scripts/uninstall.sh" --root "$target" --remove-protection; then echo 'deleted modified managed files'; exit 1; fi
[[ -x "$target/usr/local/sbin/ssh-protecter" ]]
cp -- "$bundle/deploy/systemd/ssh-protecter.service" "$unit"
bash "$bundle/scripts/uninstall.sh" --root "$target" --remove-protection --dry-run
[[ -x "$target/usr/local/sbin/ssh-protecter" ]]
bash "$bundle/scripts/uninstall.sh" --root "$target" --remove-protection
[[ ! -e "$target/usr/local/sbin/ssh-protecter" ]]
[[ -f "$target/etc/ssh-protecter/bootstrap.json" && -f "$target/var/lib/ssh-protecter/state.db" && -f "$target/etc/systemd/system/unrelated.service" ]]
bash "$bundle/scripts/uninstall.sh" --root "$target" --remove-protection --purge-data
[[ ! -e "$target/etc/ssh-protecter/bootstrap.json" && ! -e "$target/var/lib/ssh-protecter/state.db" ]]
[[ -f "$target/etc/systemd/system/unrelated.service" ]]
echo 'PASS: offline installer/uninstaller, idempotency, ownership, dry-run and private-data retention.'
