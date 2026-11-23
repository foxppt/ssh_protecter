#!/usr/bin/env bash
# Explicit target-host validation. Does not reboot or modify the system clock.
set -euo pipefail
[[ ${1:-} = --test-host ]] || { echo 'Usage: fault-check.sh --test-host watchdog|config-corrupt' >&2; exit 2; }
mode=${2:?missing mode}
[[ $(id -u) = 0 ]] || { echo 'Require local root console.' >&2; exit 1; }
systemctl is-active --quiet ssh-protecter.service
case "$mode" in
 watchdog)
  old_pid=$(systemctl show ssh-protecter.service -p MainPID --value)
  [[ "$old_pid" =~ ^[1-9][0-9]*$ ]] || exit 1
  cleanup() { if [[ $(systemctl show ssh-protecter.service -p MainPID --value) = "$old_pid" ]]; then systemctl kill --kill-whom=main --signal=CONT ssh-protecter.service || true; fi; }
  trap cleanup EXIT
  systemctl kill --kill-whom=main --signal=STOP ssh-protecter.service
  for ((i=0;i<110;i++)); do
   new_pid=$(systemctl show ssh-protecter.service -p MainPID --value)
   if [[ "$new_pid" =~ ^[1-9][0-9]*$ && "$new_pid" != "$old_pid" ]] && systemctl is-active --quiet ssh-protecter.service; then
    /usr/sbin/nft list table inet ssh_protecter >/dev/null
    echo 'PASS: stopped process replaced, service ready, protection table present.'; exit 0
   fi
   sleep 1
  done
  echo 'FAIL: watchdog did not restore the service within 110 seconds.' >&2; exit 1
  ;;
 config-corrupt)
  config=/etc/ssh-protecter/config.yaml; snapshot=/etc/ssh-protecter/bootstrap.json
  backup=$(mktemp /etc/ssh-protecter/.fault-config.XXXXXX); cp -p -- "$config" "$backup"
  cleanup() { mv -fT -- "$backup" "$config"; }; trap cleanup EXIT
  before=$(sha256sum "$snapshot" | cut -d ' ' -f 1)
  printf '\nunknown_fault_injection_field: true\n' >> "$config"
  if /usr/local/sbin/ssh-protecter reload; then echo 'FAIL: invalid configuration accepted.' >&2; exit 1; fi
  [[ "$before" = "$(sha256sum "$snapshot" | cut -d ' ' -f 1)" ]]
  systemctl is-active --quiet ssh-protecter.service; /usr/sbin/nft list table inet ssh_protecter >/dev/null
  echo 'PASS: corrupted configuration rejected; effective snapshot and running service retained.'
  ;;
 *) echo 'Unknown validation mode.' >&2; exit 2;;
esac
