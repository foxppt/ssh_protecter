#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-install.sh"
# Recognize both distro names, including dependencies from earlier installations.
for name in ssh.service sshd.service ssh.socket sshd.socket; do
  ssh_drop="/etc/systemd/system/$name.d/50-ssh-protecter.conf"
  if [[ -f "$root$ssh_drop" ]] && [[ " ${paths[*]} " != *" $ssh_drop "* ]]; then paths+=("$ssh_drop"); fi
done
for p in "${paths[@]}"; do reject_symlink_parents "$p"; check_owned "$p"; done
if ((!remove_protection)); then echo 'Uninstall removes SSH gate protection; explicitly pass --remove-protection (or combine with --dry-run).' >&2; exit 2; fi
echo 'Remove only managed service files and inet ssh_protecter table; preserve all other firewall rules.'
if ((!purge)); then echo 'Config, authenticator and database will be retained.'; else echo 'Explicit purge: remove known config, identity and database files.'; fi
if ((dry_run)); then printf '%s\n' "${paths[@]}"; exit 0; fi
if [[ -z "$root" ]]; then
  [[ -x /usr/sbin/nft && -d /run/systemd/system ]] || { echo 'Require nftables and systemd.' >&2; exit 1; }
  exec 9>/run/ssh-protecter-install.lock; flock -n 9 || exit 1
  if systemctl cat ssh-protecter.service >/dev/null 2>&1; then systemctl stop ssh-protecter.service; fi
  [[ ! -L /run/ssh-protecter.lock ]] || { echo 'Refusing symlink writer lock.' >&2; exit 1; }
  exec 8>>/run/ssh-protecter.lock; flock -n 8 || { echo 'Another firewall writer is running.' >&2; exit 1; }
  systemctl disable ssh-protecter.service ssh-protecter-guard.service 2>/dev/null || true
fi
# Remove sshd dependencies and reload their graph BEFORE stopping guard; otherwise
# Requires= could propagate the stop to sshd and disconnect existing sessions.
for p in "${paths[@]}"; do
  case "$p" in */ssh.service.d/*|*/sshd.service.d/*|*/ssh.socket.d/*|*/sshd.socket.d/*) rm -f -- "$root$p";; esac
done
if [[ -z "$root" ]]; then
  systemctl daemon-reload
  if systemctl cat ssh-protecter-guard.service >/dev/null 2>&1; then systemctl stop ssh-protecter-guard.service; fi
  /usr/sbin/nft destroy table inet ssh_protecter
fi
for p in "${paths[@]}"; do rm -f -- "$root$p"; done
rm -f -- "$manifest"
if ((purge)); then
  for p in /etc/ssh-protecter/config.yaml /etc/ssh-protecter/bootstrap.json /var/lib/ssh-protecter/state.db /var/lib/ssh-protecter/state.db-wal /var/lib/ssh-protecter/state.db-shm; do reject_symlink_parents "$p"; rm -f -- "$root$p"; done
fi
if [[ -z "$root" ]]; then systemctl daemon-reload; fi
echo 'Uninstallation completed. SSH daemon was not restarted.'
