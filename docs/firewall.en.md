# Firewall execution

[English](firewall.en.md) | [简体中文](firewall.md) | [Documentation home](../README.en.md)

Implemented components include rule generation, kernel validation before application, a Linux cross-process writer lock, systemd baseline protection, initialization, runtime grant coordination, and configuration reload. The service rebuilds its rules every ten seconds to repair damage. Rocky Linux 10 acceptance is still pending.

## Offline preview

```sh
go run ./cmd/ssh-protecter firewall-plan --config configs/config.example.yaml
```

By default the preview contains only permanent allowlist and baseline deny rules. Add `--restore` to include unexpired grants from an existing database. A missing database is an error and is not created. Previewing never invokes nft.

The renderer accepts parsed IPs and ports, preventing configuration-based nft command injection. The default table, `inet ssh_protecter`, is reserved for this program; do not add unrelated rules there. `destroy table` and recreation form one nft batch and must not be executed separately. Validate the syntax against the actual Rocky Linux 10 nftables version.

The INPUT base chain directs only enabled address families and protected TCP ports into the gate's decision chain. Established connections are preserved first; other connections must match permanent or temporary sets. Docker forwarding, NAT, and other tables are not modified. Drops in other firewalls can still prevent access.

## Deadlines and uncertain results

Temporary element lifetimes are computed from the original persisted deadline, including a second calculation after validation and before submission. The executor reserves a two-second application budget and uses the same command timeout to account for relative kernel timeouts starting at commit. Restored network access may therefore expire approximately two seconds before the recorded deadline. It does not receive a fresh five-minute duration. Sub-millisecond remainders are rounded down.

A command timeout does not prove that the kernel missed the commit. The service persists an authenticated grant intent before kernel submission and returns success only after kernel confirmation. On failure, new grants are suspended until a successful rebuild or restart recovery. A failed or lost response may still lead to access under the persisted deadline; restoration does not add time.

## Boot baseline

```sh
ssh-protecter guard --snapshot /etc/ssh-protecter/bootstrap.json
```

Actual application requires local root on Linux. Guard reads a versioned, confirmed enrollment snapshot without loading web certificates or opening the grant database. It applies baseline deny and permanent allowlist rules only; the main service restores unexpired temporary grants.

The snapshot is generated after successful TOTP enrollment and stores the root-private authenticator secret. Missing, uninitialized, or invalid snapshots make guard fail without clearing existing rules. Never include snapshot contents in logs or troubleshooting screenshots.

The `deploy/systemd` directory contains guard, the runtime service, and SSH service/socket dependency drop-ins. Complete enrollment, validation, and baseline application before installing them. A missing snapshot prevents SSH startup. Use the socket drop-in only with actual SSH socket activation. Test these dependencies on a Rocky Linux 10 host with console recovery.

Guard is a oneshot unit, not another resident monitor. It has no rule-deleting `ExecStop`. Routine main-service restarts must not restart guard or sshd. Do not make guard `PartOf` the web service.

## Tests

Portable tests cover address-family switches, IP injection and mapped addresses, expired records, check-before-apply ordering, rejection without application, and lifetime recalculation after validation delays.

An opt-in Linux integration test checks real nft syntax, repeated replacement, and preservation of this and other tables in a new network namespace. It requires root, `unshare`, and `/usr/sbin/nft`:

```sh
SSH_PROTECTER_NFT_TEST=1 go test -v -run TestKernelNamespace ./internal/firewall
```

All test rules are confined to the new namespace. Host rules are not modified. This does not replace real SSH traffic, Docker, or boot-order acceptance. Windows cannot run this kernel test; successful Linux cross-compilation is not a passing test.

References: [nft manual](https://www.netfilter.org/projects/nftables/manpage.html), [systemd dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
