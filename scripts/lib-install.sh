#!/usr/bin/env bash
# Shared, deliberately fixed paths. Never execute manifest contents as shell code.
set -euo pipefail
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=""; dry_run=0; purge=0; remove_protection=0
binary="$bundle/dist/ssh-protecter-linux-amd64"
config_source="$bundle/configs/config.example.yaml"
while (($#)); do
  case "$1" in
    --root) root=${2:?missing root}; shift 2;;
    --binary) binary=${2:?missing binary}; shift 2;;
    --config) config_source=${2:?missing config}; shift 2;;
    --dry-run) dry_run=1; shift;;
    --purge-data) purge=1; shift;;
    --remove-protection) remove_protection=1; shift;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2;;
  esac
done
if [[ -n "$root" ]]; then
  [[ "$root" = /* && "$root" != / ]] || { echo '--root must name a non-root absolute staging directory' >&2; exit 2; }
  root=$(realpath -m -- "$root")
  [[ "$root" != / ]] || exit 2
else
  [[ $(id -u) = 0 ]] || { echo 'Run as local root, or use --root for offline staging.' >&2; exit 1; }
fi
paths=(
 /usr/local/sbin/ssh-protecter
 /etc/systemd/system/ssh-protecter-guard.service
 /etc/systemd/system/ssh-protecter.service
 /etc/systemd/system/sshd.service.d/50-ssh-protecter.conf
)
sources=(
 "$binary"
 "$bundle/deploy/systemd/ssh-protecter-guard.service"
 "$bundle/deploy/systemd/ssh-protecter.service"
 "$bundle/deploy/systemd/sshd.service.d/ssh-protecter.conf"
)
# Only add socket dependencies when socket activation actually exists.
if [[ -z "$root" ]] && systemctl cat sshd.socket >/dev/null 2>&1; then
  paths+=(/etc/systemd/system/sshd.socket.d/50-ssh-protecter.conf)
  sources+=("$bundle/deploy/systemd/sshd.socket.d/ssh-protecter.conf")
fi
manifest="$root/var/lib/ssh-protecter/install.manifest"
sha() { sha256sum -- "$1" | cut -d ' ' -f 1; }
recorded_hash() { [[ ! -f "$manifest" ]] || awk -v name="$1" '$2==name {print $1}' "$manifest"; }
check_owned() {
  local dest=$1 desired=${2:-} actual expected
  [[ ! -e "$root$dest" && ! -L "$root$dest" ]] && return 0
  [[ -f "$root$dest" && ! -L "$root$dest" ]] || { echo "Refusing non-regular/symlink managed path: $dest" >&2; return 1; }
  if [[ -n "$desired" ]] && cmp -s -- "$root$dest" "$desired"; then return 0; fi
  actual=$(sha "$root$dest"); expected=$(recorded_hash "$dest")
  [[ -n "$expected" && "$actual" = "$expected" ]] || { echo "Refusing to overwrite/delete unowned or modified file: $dest" >&2; return 1; }
}
reject_symlink_parents() {
  local p="$root$1"
  while [[ "$p" != / && "$p" != "$root" ]]; do
    [[ ! -L "$p" ]] || { echo "Refusing symlink path: $p" >&2; return 1; }
    p=$(dirname -- "$p")
  done
}
for p in "${paths[@]}" /etc/ssh-protecter/config.yaml /var/lib/ssh-protecter/install.manifest; do reject_symlink_parents "$p"; done
atomic_copy() {
  local src=$1 dest=$2 mode=$3 tmp
  mkdir -p -- "$(dirname -- "$dest")"
  tmp=$(mktemp "$(dirname -- "$dest")/.ssh-protecter-install.XXXXXX")
  if ! install -m "$mode" -- "$src" "$tmp"; then rm -f -- "$tmp"; return 1; fi
  mv -fT -- "$tmp" "$dest"
}
write_manifest() {
  local tmp p
  mkdir -p -- "$(dirname -- "$manifest")"
  tmp=$(mktemp "$(dirname -- "$manifest")/.manifest.XXXXXX")
  for p in "${paths[@]}"; do [[ ! -f "$root$p" ]] || printf '%s %s\n' "$(sha "$root$p")" "$p" >> "$tmp"; done
  chmod 600 -- "$tmp"; mv -fT -- "$tmp" "$manifest"
}
