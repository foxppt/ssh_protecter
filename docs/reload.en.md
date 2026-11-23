# Configuration reload and failure recovery

[English](reload.en.md) | [简体中文](reload.md) | [Documentation home](../README.en.md)

## Usage

Edit the YAML path used to start the service, then check and reload it:

```sh
ssh-protecter config-check --config /etc/ssh-protecter/config.yaml --resources
ssh-protecter reload
# With the project's systemd unit installed:
systemctl reload ssh-protecter
```

`reload` requests a reload over `/run/ssh-protecter/admin.sock` and waits for the result. The directory is mode 0700 and the socket 0600, for local root only. The service rereads its original configuration path; clients cannot upload configuration or select another path. With a custom socket, the CLI and unit's `ExecReload` must use the same address.

A successful exit confirms application. Failure returns a nonzero exit code, including through systemctl; merely sending a signal is not treated as success. A disconnected or timed-out client may have an unknown result: inspect service logs before retrying. There is no public HTTP administrative endpoint.

## Reloadable settings

- Protected SSH ports, IPv4/IPv6 protection, and permanent IP allowlist.
- Duration of subsequent grants, failure-counting window and threshold, and duration of subsequent bans.
- Trusted proxy ranges.
- Direct TLS certificate and private-key paths and contents.

Existing grant and ban deadlines do not change. A larger failure window can only include retained events; deleted history cannot be reconstructed. Removing ports or disabling an address family reduces protection, so settings must reflect the actual sshd listeners.

Listener address, direct/proxy mode, and database path cannot change through reload. Such changes are rejected before application.

## Certificate renewal

After an external tool updates certificate files, invoke either reload command. The service loads the full certificate and matching key before publishing them through an atomic pointer. Subsequent TLS handshakes use the new certificate; existing connections remain. Failed loading retains the old certificate in memory.

In Nginx mode, external tooling must validate and reload Nginx. This service does not replace Nginx certificates. Loading a certificate/key pair does not validate trust chains, hostnames, or expiry; renewal tooling remains responsible for those checks.

## Application and rollback

1. Strictly parse and validate the entire configuration and prepare certificates.
2. Acquire the state lock shared with authorization and rule restoration; reject settings that cannot be changed live.
3. Read original grant deadlines, generate the new firewall plan, validate it in the kernel, then submit the program's rules.
4. Persist the new identity, baseline rules, and full effective configuration in one private file, using file fsync, atomic rename, and directory fsync.
5. Publish the in-memory configuration and prepared certificates, then return success.

Configuration files, kernel rules, and process memory do not share a transaction. The effective snapshot is the crash-recovery commit point: a crash before its commit restores the old generation; a crash after commit restores the new generation. Startup first applies snapshot baseline protection, then restores temporary grants.

On application failure the service resubmits the old firewall. A persistence error also triggers an attempt to persist the old snapshot, even when the rename may already have happened. Confirmed rollback retains the old service state. If rollback cannot be confirmed, the service stops accepting new grants and fails health checks so systemd can restart it from the disk snapshot. Logs report this fault; the old configuration cannot be assumed to remain effective.

Invalid edits do not overwrite the committed snapshot. Ordinary restart uses the last successfully applied full configuration instead of activating rejected YAML changes. The administrator's YAML is neither rewritten nor deleted.

## Offline listener changes

To switch direct/Nginx mode or listener address, stop the authorization service without stopping sshd, then run from a local root console:

```sh
ssh-protecter configure --config /etc/ssh-protecter/config.yaml
```

The command acquires the same cross-process writer lock, validates configuration and certificates, and commits rules and the effective snapshot. Start the service afterward. The command fails if the running service still holds the lock. Failures use the same rollback logic.

Changing the database path still requires a separate migration. Do not delete the identity snapshot or substitute an empty database to bypass restrictions.

## Verification limits

Portable tests cover effective configuration and snapshot recovery, deadline preservation, kernel and persistence failures, rollback errors, rejected live changes, concurrent grants/reloads, and actual local TLS handshakes observing certificate switching and retention after invalid updates.

Unix-socket completion and permission tests were run on AlmaLinux 10.1 WSL. See [operations](operations.en.md) for hang recovery and other faults. Target-host nftables, Docker, SELinux, full boot, and power-loss recovery still require acceptance. CGO was disabled in the development environment and the Go race detector was not run.
