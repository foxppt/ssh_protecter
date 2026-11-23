# Deploying and verifying on Rocky Linux 10

[English](deployment.en.md) | [简体中文](deployment.md) | [Documentation home](../README.en.md)

The main authorization flow and configuration reloads are implemented. Target-platform acceptance is not complete. These instructions are for test hosts with a cloud console, VNC, or physical terminal recovery path. Linux deployment has not been performed on the Windows development host.

## Prerequisites and files

Install nftables tools and ensure `/usr/sbin/nft` exists. Existing firewalld rules must allow the configured SSH and HTTPS ports: this program adds IP restrictions and cannot override drops in other chains. Do not enable loading scripts that flush the entire ruleset, or disable Docker's firewall management. Keep SELinux enabled and grant necessary permissions based on audit results.

Build a Linux binary and install it at `/usr/local/sbin/ssh-protecter`. Put configuration at `/etc/ssh-protecter/config.yaml`, owned by root, with mode 0700 for its directory and 0600 for the file. Initialization creates the default state directory, `/var/lib/ssh-protecter`. A custom state path requires corresponding systemd writable-directory changes.

The default protection snapshot is `/etc/ssh-protecter/bootstrap.json`. It contains the authenticator secret; back it up as a private credential.

Ensure system time is synchronized. Kernel synchronization status, a persisted time high-water mark, and runtime monotonic-clock checks protect grant restoration. See [clock recovery](operations.en.md#clock-protection-across-reboots).

## Direct HTTPS

Use `configs/config.example.yaml`. Obtain certificates using an external tool and configure the certificate chain and private-key paths:

```sh
ssh-protecter config-check --config /etc/ssh-protecter/config.yaml --resources
ssh-protecter init --config /etc/ssh-protecter/config.yaml
ssh-protecter serve --config /etc/ssh-protecter/config.yaml
```

Run `init` in an interactive terminal. Default deny is installed only after a valid code confirms enrollment. The first interactive `serve` can perform the same initialization; a background systemd service cannot wait for enrollment input.

The CLI generates a black-and-white terminal QR code locally. Add it to Google Authenticator, Microsoft Authenticator, or another TOTP app and enter the six-digit code. `rebind` uses the same flow.

The secret and `otpauth://` URI are also displayed for manual enrollment: time-based, SHA1, six digits, 30 seconds. No external QR service is used and no image file is automatically saved. The terminal needs Unicode half-block characters and ANSI colors. If it is too narrow, enlarge it or use the manual secret. Older terminals can use `init --qr=false` or `rebind --qr=false`.

Renew certificates externally. After replacement, run `ssh-protecter reload` or `systemctl reload ssh-protecter` to validate and switch certificates without restarting sshd. A failed load retains the old certificate in memory. See [reload behavior](reload.en.md).

## Nginx reverse proxy

Use `configs/nginx.example.yaml`: Go listens on `127.0.0.1:8080`, trusts only `127.0.0.1/32`, and has explicitly empty certificate paths. Adapt the hostname and certificate paths in `deploy/nginx/ssh-protecter.conf`.

The example overwrites source headers to prevent forwarding client-forged values. Browsers must use Nginx's HTTPS address. Do not expose port 8080 publicly. Request protection requires Secure cookies; direct browser authorization over HTTP is unsupported.

Validate and reload Nginx after configuration or certificate updates. If SELinux blocks loopback proxy connections, grant access according to audit results and local policy rather than disabling SELinux globally. For multiple proxy hops, explicitly define every trusted range.

## systemd

1. Complete `init` and verify that enrollment and baseline protection succeed.
2. Install `deploy/systemd/ssh-protecter-guard.service` and `ssh-protecter.service` into `/etc/systemd/system/`.
3. Install the SSH service drop-in into the corresponding `sshd.service.d` directory. Install the socket drop-in only when SSH socket activation is actually used.
4. Check the units with `systemd-analyze verify`, then run `systemctl daemon-reload`.
5. Start guard, verify success, and enable guard and the authorization service at boot. Do not restart sshd for this step. Keep the current session and verify new SSH connections with console recovery available.

At startup the authorization service applies the last confirmed baseline, restores unexpired database grants, then opens its web listener. Watchdog heartbeats depend on database checks, rule restoration, and local HTTP health probes. Stopping the service does not delete kernel rules. A boot-time protection failure should prevent SSH from starting; validate actual service/socket dependencies on the target host.

## Lost authenticator

From a local root console, stop the authorization service, then run:

```sh
ssh-protecter rebind --config /etc/ssh-protecter/config.yaml
```

Confirm a code from the new authenticator and start the service. Rebinding cannot run alongside the service because of its exclusive firewall lock. It revokes temporary grants, retaining ban records, the permanent allowlist, and established SSH connections.

## Change limitations

- Activate policy edits with `reload`. Ordinary restarts use the last successfully applied snapshot. To change the listener or switch direct/proxy mode, stop the service, run `configure`, then start it. Do not delete snapshots to bypass checks.
- The database path is bound to the initialized identity. Changing it to clear restrictions is unsupported.
- See [operations](operations.en.md) for installation, uninstallation, and fault tools. The first version has no web account management.
- Network, firewall, Docker, and boot behavior still require the [target-host acceptance plan](technical-design.en.md#9-acceptance-plan). Local Go tests and cross-compilation cannot prove these properties.
