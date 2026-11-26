# Installation, uninstallation, and fault verification

[English](operations.en.md) | [简体中文](operations.md) | [Documentation home](../README.en.md)

## Included tools

- `scripts/install.sh`: installs the binary and systemd files, performs terminal enrollment on first installation, then enables boot protection.
- `scripts/uninstall.sh`: removes only project-managed files and the independent firewall table, according to the installation manifest.
- `scripts/run-fault-tests.sh`: runs packaged Linux test binaries without requiring Go on the target host.
- `scripts/fault-check.sh`: checks hang recovery and invalid-configuration rejection on the actual installed test service; requires explicit `--test-host`.
- `scripts/verify-reboot.py`: verifies deadlines and startup order in separate pre/post-reboot steps. It does not reboot the server.

Full-machine reboot, real SSH traffic, and final Rocky Linux 10 acceptance must be checked by the operator on a test host. Automated coverage below is distinct from pending target-host acceptance.

## Automatic installation

The current package is `dist/ssh-protecter-0.1.0-rc4-linux-amd64.tar.gz`, accompanied by a `.sha256` checksum file. After extracting it, run `sha256sum -c dist/SHA256SUMS` from the package root to verify packaged files. The package includes the executable and fault-test binaries; Go is not required on the target. rc2 adds terminal enrollment QR codes, whose rendered content is verified by decoding with an independent decoder.

Extract the release and enter its root directory. Choose direct TLS or Nginx configuration, then edit addresses, certificates, and the permanent allowlist following [deployment](deployment.en.md). Administrators must check and install Nginx configuration themselves; the installer does not overwrite other sites.

```sh
bash scripts/install.sh --config configs/nginx.example.yaml --dry-run
bash scripts/install.sh --config configs/nginx.example.yaml
```

Use `--binary /absolute/path/ssh-protecter` to select a binary. Live installation requires local root, running systemd, `/usr/sbin/nft`, `flock`, `systemd-analyze`, and `restorecon`. It does not install system packages, disable SELinux, change Docker's backend, or modify existing firewalld rules.

The installer validates configuration and certificates and retains existing configuration, authenticator credentials, and database. First installation requires a valid TOTP code in an interactive terminal. SSH dependencies are installed only after baseline rules apply successfully. It then installs units, checks startup, and enables boot startup. Installation and upgrades do not restart sshd. An existing authorization service is stopped first to release its exclusive firewall lock.

Managed installation uses fixed configuration, snapshot, and state paths. A custom database path is rejected to keep systemd writable directories and uninstall scope consistent; use manual deployment with adapted units instead. An existing effective snapshot remains authoritative. YAML edits require `reload` or `configure`; upgrading does not activate draft edits.

The installation manifest stores hashes of fixed managed files. Reinstallation checks ownership and refuses to overwrite unrelated or manually modified files. On errors it retains completed protection steps and private data; fix the issue and rerun. There is no shared transaction across systemd, filesystem, and kernel changes. If installation stops after enrollment, repair it through the console and rerun rather than deleting state files.

`--root /absolute/staging/directory` stages files offline without running init/systemctl/nft or changing host services. A staged image still needs enrollment and startup verification before use. Passing staging tests does not establish successful live installation.

## Automatic uninstallation

Uninstallation removes the additional SSH network restriction and therefore requires an explicit option:

```sh
bash scripts/uninstall.sh --remove-protection --dry-run
bash scripts/uninstall.sh --remove-protection
```

Configuration, authenticator credentials, and the database are retained by default. Add `--purge-data` to delete those too. Only fixed known files are deleted; user directories are not recursively removed. Other user files and firewall tables remain. Manually modified managed files cause uninstallation to exit before system changes, allowing the administrator to resolve conflicts first.

Order: stop the authorization service, disable boot startup, remove SSH dependencies, reload systemd's dependency graph, stop guard, then remove the project's table and files. This avoids propagating a guard stop to sshd through `Requires`. Neither installer nor uninstaller actively restarts SSH.

## Clock protection across reboots

```yaml
clock:
  require_sync: true
  max_skew: 2s
```

Older effective snapshots receive these defaults on load. Database schema version 1 migrates automatically to version 2, preserving grants, failure records, and ban deadlines.

By default, read-only `adjtimex` checks kernel synchronization status before accepting grants, restoring temporary grants, or changing configuration. While unsynchronized, the service does not advance persisted time records from a potentially incorrect RTC or restore temporary grants. systemd retries until chronyd/NTP reports synchronization. Permanent allowlist entries and established SSH connections remain.

Each authorization-related clock check persists the highest observed wall time. If time after restart is significantly behind this record, a persistent fault flag is set. At runtime, wall-clock progress is compared with an independent monotonic clock to detect significant forward or backward jumps. Restarting does not clear the fault. On detection, the service attempts to remove temporary allowlist entries, retaining baseline rules, and suspends new grants.

`max_skew` permits small clock corrections; it does not extend TOTP or grant lifetimes. Setting `require_sync: false` explicitly reduces startup time-trust requirements and is intended only for controlled offline experiments. High-water marks and runtime jump detection remain. The service trusts OS/NTP synchronization status, not an independent trusted time source. Local persisted data alone cannot distinguish a long shutdown from a clock advanced while offline.

To recover, stop the authorization service from a local root console, correct and synchronize system time, then run:

```sh
ssh-protecter clock-reset --revoke-grants
systemctl start ssh-protecter
```

Recovery always requires synchronized time. It explicitly revokes all temporary grants and resets the time record and fault flag. Existing ban and failure timestamps are unchanged; recovery does not silently clear bans. A missing or corrupt database causes failure instead of silently recreating an empty database. Restore it from a trusted backup.

## Isolated fault tests

The Linux release includes precompiled tests:

```sh
bash scripts/run-fault-tests.sh
```

Requires root, systemd, `unshare`, and nftables. Tests use temporary directories, isolated mount/network namespaces, and uniquely named, time-limited transient systemd units. They do not modify active sshd or the project's installed service. Restricted environments without nftables may explicitly use `--skip-nft`; output marks the skipped coverage, which is not full acceptance.

| Fault | Automated method | Expected behavior |
| --- | --- | --- |
| Process hang | Send SIGSTOP to a child in a transient systemd unit | Watchdog kills and restarts it; the replacement sends healthy heartbeats |
| Storage full | Fill an 8 MiB tmpfs in an isolated mount namespace; separately trigger SQLITE_FULL with a page limit | Writes fail without committing new grants; old data is recoverable after space is freed |
| Read-only, corrupt, or missing database | Real read-only connections and corrupt/missing files | Fail without opening ports or silently recreating restrictions |
| Invalid configuration | Load malformed YAML, unknown fields, or missing certificates through the actual loader | Retain in-memory configuration and last effective snapshot |
| Interrupted reload | Parent kills child before and after snapshot commit | Recover old/new configuration according to commit point; preserve grant deadlines |
| Clock fault | Reopen database after restart; simulate wall/monotonic divergence | Reject rollback and runtime jumps; retain faults across processes |
| Install/uninstall | Run real shell tools against a staging directory | Verify idempotence, dry runs, ownership checks, retained private data, and explicit purging |

Portable portions were run on Windows. Linux hang recovery, real tmpfs ENOSPC, clock/state/reload faults, and staged installation were tested on local AlmaLinux 10.1 WSL. That WSL environment lacked nftables, so real nft rule tests were not run. These results do not establish full Rocky Linux 10 boot/network acceptance.

## Check the installed test service

On a test host with console recovery:

```sh
bash scripts/fault-check.sh --test-host watchdog
bash scripts/fault-check.sh --test-host config-corrupt
```

The first pauses the actual authorization process and waits up to approximately 110 seconds for automatic recovery; on failure it attempts to resume the original process. The second temporarily adds invalid configuration, verifies reload rejection and an unchanged snapshot, and restores the file on exit. Do not edit configuration concurrently.

## Full-machine reboot acceptance

Through the web page, first create at least one valid temporary grant and one verification-entry ban. Then run from the console with Python 3:

```sh
python3 scripts/verify-reboot.py prepare
```

Manually reboot the test host. Do not renew grants afterward. Wait for time synchronization and service readiness, then run:

```sh
python3 scripts/verify-reboot.py check
```

The script verifies a changed boot ID, identical deadlines for unexpired grants/bans, no restoration of expired records, and guard readiness before the SSH listener. Use a new `--record` path for each round or move the previous record manually. It does not reboot the server or change system time.

From another device, also verify unauthorized SSH rejection, access after authorization, established-session preservation after expiry, and coexistence with Docker/firewalld/SELinux. Source tests and time records cannot replace these network checks.

References: [Linux adjtimex](https://man7.org/linux/man-pages/man2/adjtimex.2.html), [systemd watchdog](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [SQLite limits](https://www.sqlite.org/limits.html).

## Ubuntu support and online revocation

The installer detects Rocky's `sshd.service/sshd.socket` and Ubuntu's `ssh.service/ssh.socket`. It uses `restorecon` when available; SELinux enforcing systems require it. The baseline guard uses `DefaultDependencies=no` to load after local filesystems and before SSH listeners without an early-boot dependency cycle. The authorization service orders after `time-sync.target`.

As local root, run `ssh-protecter revoke --ip 203.0.113.10` (replace the example address). The running service deletes the persisted temporary grant and reconciles its firewall rules through a private Unix socket. Established sessions remain connected. Repeating the command is safe, and reconciliation or restart cannot restore the deleted grant. A firewall failure returns an error without restoring the persisted grant; check service health before treating revocation as complete. The command does not ban browser authentication.

Permanent allowlist entries must first be removed from `ssh.permanent_allow_ips` and applied with `ssh-protecter reload`; then revoke any remaining temporary grant. IPv6 is supported. The anonymized [Ubuntu acceptance record](acceptance-ubuntu-20261126.md) describes host tests and their limits.
