# ssh-protecter

[English](README.en.md) | [简体中文](README.md)

A Go SSH access gate targeting Rocky Linux 10. Authenticate in a browser with a TOTP code to temporarily allow an IP address to establish SSH connections. SSH authentication remains separate and is still required.

**Development release. Final acceptance testing on Rocky Linux 10 is still pending.** Use a test server with an independent console recovery path. Automated tests and cross-compilation do not establish production readiness.

## How it works

1. Bind an authenticator from a local interactive terminal and confirm a valid code before enabling default-deny protection.
2. Open the HTTPS authorization page and enter a TOTP code. The target IP defaults to the request source IP; a different IPv4 or IPv6 address can be entered manually.
3. The service persists the grant and applies its nftables rules. A successful response is returned only after the kernel confirms application.
4. When the grant expires, new connections are denied. Established SSH connections are not actively disconnected.

The default grant lasts five minutes. Renewing replaces the deadline with a new deadline measured from the latest successful authorization; remaining time is not added. Every authorization or renewal requires a code.

## Features

- Strict YAML validation, including unknown and duplicate fields, ports, addresses, durations, and unsafe proxy listener settings.
- Configurable protected TCP ports, IPv4/IPv6 protection, permanent IP allowlist, grant duration, and verification failure policy.
- SQLite persistence for grant deadlines, failure events, and verification-entry ban deadlines. Restarts preserve original deadlines.
- Rolling failure limits per request source IP. Further failures during a ban do not extend its deadline. IPv4-mapped IPv6 addresses are normalized.
- An independent nftables table with permanent and expiring address sets, checked before replacement in a single batch. Linux writers share a cross-process lock; other platforms refuse actual application.
- Local terminal QR-code enrollment, browser TOTP verification, CSRF checks, and explicit trusted-proxy handling.
- Direct HTTPS or Nginx TLS termination, local health probes, systemd watchdog support, and periodic rule repair.
- Local authenticator rebinding that revokes temporary grants while retaining permanent allowlist entries and established SSH connections.
- Validated configuration and certificate reloads, rollback on failure, and restart recovery from the last successfully applied configuration.
- Persistent clock high-water marks and fault flags, synchronization checks, and explicit local recovery.
- Installation, uninstallation, isolated fault tests, and reboot-verification tools.

## Get started

For a packaged installation, configure TLS or Nginx first, then run from an interactive root terminal on the test server:

```sh
bash scripts/install.sh --config configs/nginx.example.yaml --dry-run
bash scripts/install.sh --config configs/nginx.example.yaml
```

See [deployment](docs/deployment.en.md) and [operations](docs/operations.en.md) for prerequisites, package verification, systemd setup, recovery, and uninstallation. The installer does not install Nginx configuration for you.

For a manual installation, place the binary and configuration as described in the deployment guide, then run:

```sh
ssh-protecter init --config /etc/ssh-protecter/config.yaml
ssh-protecter serve --config /etc/ssh-protecter/config.yaml
```

Enrollment displays a locally generated QR code and a manual secret. Scan it with a TOTP authenticator, then confirm the six-digit code. `--qr=false` disables the QR display. Codes are entered without echo. The QR code and secret are credentials: do not record or share the terminal output. No external QR service is used and no image is automatically saved.

An already enrolled identity is not initialized again. An uninitialized background process without a terminal fails rather than waiting for input. Stop the authorization service before running `rebind`; the running service holds the exclusive writer lock. Stopping it does not remove firewall rules or stop sshd.

## Build and inspect

Requires Go 1.26.1 or later. The SQLite driver is pure Go and does not require CGO.

```sh
go test ./...
go vet ./...
go build -o ssh-protecter ./cmd/ssh-protecter
go run ./cmd/ssh-protecter config-check --config configs/config.example.yaml
```

Read-only commands do not change the firewall:

```sh
ssh-protecter config-check --config /etc/ssh-protecter/config.yaml --resources
ssh-protecter state-inspect --config /etc/ssh-protecter/config.yaml
ssh-protecter firewall-plan --config /etc/ssh-protecter/config.yaml
```

`config-check` validates configuration; `--resources` additionally loads the certificate and matching private key in direct TLS mode. Neither proves that a port can be bound, a certificate is valid for its hostname or dates, or firewall/systemd integration works.

`state-inspect` reports unexpired persisted **desired state**, not verified kernel rules. It does not create a missing database. Deadlines are UTC Unix seconds. `firewall-plan --restore` includes unexpired persisted grants in the preview without applying rules.

On Linux, root execution of `init`, `rebind`, `guard`, `configure`, `reload`, `clock-reset`, or `serve` can apply protection rules. There is no CLI command that grants access without identity verification.

## Configuration

Use [the direct TLS example](configs/config.example.yaml) or [the Nginx example](configs/nginx.example.yaml). Durations such as `5m`, `1h`, and `24h` must be positive whole seconds. Permanent allowlist entries are individual IP addresses, not hostnames or CIDR ranges.

For a reverse proxy, select `http.mode: reverse_proxy`, use a loopback IP listener, specify trusted proxy CIDRs, and explicitly set `tls_cert_file` and `tls_key_file` to empty strings. Direct mode ignores source headers. Browser access requires HTTPS in both modes.

Disabling `protect_ipv4` or `protect_ipv6` removes this program's protection for that address family; it does not disable the system protocol. Removing a protected port likewise removes this program's restriction on that port.

## Security and operational boundaries

- IP authorization cannot distinguish devices sharing a public NAT address. Continue to use SSH's own authentication and account controls.
- Valid TOTP codes are intentionally reusable within the acceptance window: SHA1, six digits, 30-second steps, and a fixed tolerance of one step in either direction. This is not a replay-resistant SPA protocol.
- SQLite and kernel updates are separate operations. A verified request whose response fails or is lost may still take effect after repair or restart, using its persisted deadline. Retrying renews from the new successful authorization time.
- Only this program's firewall table is managed. An accept here cannot override another firewall's drop. External deletion of rules creates a detection and repair window.
- Persistence assumes a reliable local filesystem. Correct time and an independent console recovery path are necessary for deployment and recovery.
- The browser authorization page currently uses Chinese text; these English documents do not change the application interface.

## Documentation

- [Deployment and TLS](docs/deployment.en.md)
- [Installation, recovery, and fault testing](docs/operations.en.md)
- [Configuration reload and rollback](docs/reload.en.md)
- [Firewall behavior and integration tests](docs/firewall.en.md)
- [Technical design draft and acceptance plan](docs/technical-design.en.md)
- [Domain terminology](CONTEXT.en.md)

The technical design records requirements and proposals; the operational guides describe implemented behavior and its verification limits. Final Rocky Linux 10 fault, boot, and network acceptance remains outstanding.
