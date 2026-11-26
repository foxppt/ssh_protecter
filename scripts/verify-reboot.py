#!/usr/bin/env python3
"""Two-phase target-host reboot verification; never initiates a reboot."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

def command(*args):
    return subprocess.check_output(args, text=True, timeout=15).strip()

def snapshot():
    return json.loads(command('/usr/local/sbin/ssh-protecter', 'state-inspect', '--config', '/etc/ssh-protecter/config.yaml'))

def property_value(unit, prop):
    return command('systemctl', 'show', unit, '-p', prop, '--value')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'check'])
    parser.add_argument('--record', default='/var/lib/ssh-protecter/reboot-check.json')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires local root')
    path = Path(args.record)
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if args.mode == 'prepare':
        current = snapshot()
        if not current['grants'] or not current['bans']:
            parser.error('first create at least one temporary grant and one verification IP ban through the webpage')
        record = {'boot_id': boot_id, 'captured_at': int(time.time()), 'snapshot': current}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(record, output)
            output.flush()
            os.fsync(output.fileno())
        print('Prepared. Reboot the test server manually; do not renew grants. Then run check.')
        return
    record = json.loads(path.read_text())
    if boot_id == record['boot_id']:
        parser.error('boot ID unchanged: a real machine reboot has not occurred')
    now = int(time.time())
    if now < record['captured_at'] - 2:
        parser.error('wall clock moved backwards')
    if property_value('ssh-protecter.service', 'ActiveState') != 'active':
        parser.error('authorization service is not ready')
    current = snapshot()
    for kind in ('grants', 'bans'):
        present = {entry['ip']: entry for entry in current[kind]}
        for entry in record['snapshot'][kind]:
            restored = present.get(entry['ip'])
            if entry['expires_at'] > now:
                if restored is None or restored['expires_at'] != entry['expires_at']:
                    parser.error(f'{kind} missing or deadline changed for {entry["ip"]}')
            elif restored is not None:
                parser.error(f'expired {kind} restored for {entry["ip"]}')
    guard_ready = int(property_value('ssh-protecter-guard.service', 'ActiveEnterTimestampMonotonic') or 0)
    ssh_unit = None
    for candidate in ('sshd.socket', 'ssh.socket', 'sshd.service', 'ssh.service'):
        try:
            if property_value(candidate, 'ActiveState') == 'active':
                ssh_unit = candidate
                break
        except subprocess.CalledProcessError:
            pass
    if ssh_unit is None:
        parser.error('no active OpenSSH service or socket found')
    ssh_start = int(property_value(ssh_unit, 'ActiveEnterTimestampMonotonic' if ssh_unit.endswith('.socket') else 'ExecMainStartTimestampMonotonic') or 0)
    if not guard_ready or ssh_start < guard_ready:
        parser.error('SSH listener did not start after baseline protection')
    command('/usr/sbin/nft', 'list', 'table', 'inet', 'ssh_protecter')
    print('PASS: real reboot, unchanged deadlines, expired entries absent, baseline before SSH.')

if __name__ == '__main__':
    main()
