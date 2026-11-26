#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib-install.sh"
[[ -f "$binary" && -f "$config_source" ]] || { echo 'Binary/config input missing.' >&2; exit 1; }
for i in "${!paths[@]}"; do check_owned "${paths[$i]}" "${sources[$i]}"; done
effective_config="$config_source"
if [[ -f "$root/etc/ssh-protecter/config.yaml" ]]; then effective_config="$root/etc/ssh-protecter/config.yaml"; fi
printf 'Install binary and systemd units; preserve existing config, identity and database.\n'
if [[ -n "$root" ]]; then printf 'Offline staging under %s; no initialization, systemctl or nft commands.\n' "$root"; fi
if ((dry_run)); then printf '%s\n' "${paths[@]}"; exit 0; fi
if [[ -z "$root" ]]; then
  for tool in systemctl systemd-analyze flock; do command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }; done
  if [[ -r /sys/fs/selinux/enforce && $(cat /sys/fs/selinux/enforce) = 1 ]] && ! command -v restorecon >/dev/null 2>&1; then
    echo 'SELinux is enforcing but restorecon is missing.' >&2; exit 1
  fi
  [[ -x /usr/sbin/nft && -d /run/systemd/system ]] || { echo 'Require nftables and running systemd.' >&2; exit 1; }
  exec 9>/run/ssh-protecter-install.lock; flock -n 9 || { echo 'Another installer is running.' >&2; exit 1; }
  "$binary" config-check --config "$effective_config" --resources --installation
  # Upgrades must release the service's firewall writer lock, never stop sshd.
  if systemctl cat ssh-protecter.service >/dev/null 2>&1; then systemctl stop ssh-protecter.service; fi
fi
trap 'echo "Installation interrupted/failed; private data and completed protection steps retained. Re-run after repair." >&2' ERR
mkdir -p -- "$root/etc/ssh-protecter" "$root/var/lib/ssh-protecter"
chmod 700 -- "$root/etc/ssh-protecter" "$root/var/lib/ssh-protecter"
[[ -f "$root/etc/ssh-protecter/config.yaml" ]] || atomic_copy "$config_source" "$root/etc/ssh-protecter/config.yaml" 600
# Install binary first; ownership manifest is updated after each completed copy.
atomic_copy "$binary" "$root${paths[0]}" 755
write_manifest
if [[ -z "$root" ]]; then
  restore_labels -F /usr/local/sbin/ssh-protecter /etc/ssh-protecter /var/lib/ssh-protecter
  if [[ ! -f /etc/ssh-protecter/bootstrap.json ]]; then
    /usr/local/sbin/ssh-protecter init --config /etc/ssh-protecter/config.yaml
  fi
  # Validate baseline before introducing any sshd startup dependency.
  /usr/local/sbin/ssh-protecter guard
  systemd-analyze verify "${sources[1]}" "${sources[2]}"
fi
for i in "${!paths[@]}"; do
  ((i==0)) && continue
  atomic_copy "${sources[$i]}" "$root${paths[$i]}" 644
  write_manifest
done
if [[ -z "$root" ]]; then
  restore_labels -RF /etc/systemd/system/ssh-protecter.service /etc/systemd/system/ssh-protecter-guard.service "/etc/systemd/system/$ssh_unit.d" /etc/ssh-protecter /var/lib/ssh-protecter
  if [[ -d "/etc/systemd/system/$ssh_socket.d" ]]; then restore_labels -RF "/etc/systemd/system/$ssh_socket.d"; fi
  systemctl daemon-reload
  systemctl start ssh-protecter-guard.service
  systemctl enable ssh-protecter-guard.service ssh-protecter.service
  systemctl start ssh-protecter.service
  systemctl is-active --quiet ssh-protecter.service
fi
trap - ERR
echo 'Installation completed. SSH daemon was not restarted.'
