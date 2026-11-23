# SSH access gate: initial technical design draft

[English](technical-design.en.md) | [简体中文](technical-design.md) | [Documentation home](../README.en.md)

Date: 2026-11-02. Target: Rocky Linux 10.

This document records confirmed requirements and proposed implementation details. It is not proof of implementation or target-system verification. Proposed details were not individually confirmed. Dependencies and kernel behavior require target-host acceptance. For implemented behavior, use [deployment](deployment.en.md), [firewall](firewall.en.md), [reload](reload.en.md), and [operations](operations.en.md). In particular, runtime reconciliation, configuration snapshots, and clock protection are described more precisely in those guides.

## 1. Confirmed behavior

| Area | Initial behavior |
| --- | --- |
| Process | Foreground Go CLI service managed by systemd |
| Users | One user initially; identity and grant structures leave room for multiple users |
| Initialization | Terminal TOTP enrollment and valid-code confirmation before default deny |
| Web authentication | TOTP only, no password; valid codes may be reused within their acceptance window |
| Source IP | Actual connection peer in direct mode; source headers only through explicitly trusted proxies |
| Target IP | Request source by default; manual IPv4 or IPv6 allowed |
| Temporary grant | Five minutes by default; renewal starts from the latest successful authorization without adding remaining time |
| Connection preservation | Expiry denies new connections only; disconnecting all sessions does not revoke early |
| Permanent allowlist | Configured IPs bypass web authorization but still need SSH authentication |
| Failures | By default, five failures per source IP in a rolling hour ban verification for 24 hours; configurable |
| Ban/allowlist separation | Permanent allowlist entries do not bypass web failure limits |
| Persistence | IPs and grant/ban deadlines survive restart with original deadlines |
| Reload | Validate before application; retain the previous effective configuration on recoverable failure |
| Network scope | Configurable IPv4/IPv6 protection and SSH ports |
| Docker | Coexistence through independent firewall objects |
| HTTPS | Go TLS termination or Nginx TLS termination and proxying |
| Certificates | External issuance and renewal, documented deployment |
| Recovery | Local root rebinding revokes temporary grants without actively disconnecting existing SSH sessions |
| Failure policy | Do not automatically open SSH; existing temporary grants expire on schedule and permanent allowlist entries remain |

## 2. Components and responsibilities

```text
Browser -- HTTPS -- [optional Nginx] -- Go authorization service
                                           |
                         persisted state --+-- independent firewall table/chains
                                           |
systemd -- startup, restart, watchdog ------+

SSH client -- kernel firewall authorization -- sshd authentication
```

One binary provides initialization, service execution, configuration checks, reloads, state inspection, and rebinding. It does not fork into the background or implement another resident process supervisor. systemd detects exits; health-dependent Go heartbeats support its watchdog. The kernel handles packet decisions and temporary-element expiration. Service exit must not remove baseline rules.

SQLite is proposed for mutable grants, bans, and failure events, keeping them separate from administrator-edited configuration.

## 3. Firewall design

### Independent objects

The proposed `inet ssh_protecter` table contains an INPUT-hook base chain, a separate SSH decision chain, protected port sets, permanent IPv4/IPv6 sets, and temporary IPv4/IPv6 timeout sets.

Replace only project-owned objects. Never use `flush ruleset` or modify Docker tables, NAT, or forwarding. Determine hook priority against actual host rules rather than assuming order from chain names.

For enabled address families and protected TCP ports:

1. Preserve established SSH connections according to connection tracking.
2. Allow permanent allowlist sources.
3. Allow temporary-grant sources.
4. Deny all remaining connections.

Other ports are outside this program's decision scope. Disabling an address family removes this restriction, not the system protocol. Temporary lifetimes are original deadline minus current time; repair, restore, and reload must not reset them to a full five minutes. Routine expiration must not depend on a Go timer deleting rules.

### Docker, firewalld, and scope

- Host SSH uses INPUT. Bridged container ports normally use DNAT/forwarding and are outside initial protection. Host-network containers binding protected ports share the host's restrictions.
- Do not use `DOCKER-USER` as the host SSH gate or require a Docker firewall backend switch.
- An nftables accept here does not override a drop in another base chain. Other firewalls must independently permit the SSH port.
- Do not enable a generic nftables service that flushes global rules merely to load this program's table.
- Record and test actual Docker version, backend, and firewalld status. Do not claim compatibility for untested combinations.

### Guarantee boundaries

Installed baseline rules survive Go crashes, termination, and normal restart; temporary elements still expire. Table lifetime must not be tied to its creating process.

The design calls for change monitoring and periodic reconciliation of project-owned objects. The current implementation periodically rebuilds rules; see [firewall behavior](firewall.en.md). External root deletion of all rules creates a detection/recovery window. Host software cannot guarantee zero-window blocking after its filters are deleted. The initial version does not add a cloud security-group control plane.

## 4. Startup, enrollment, and supervision

### First enrollment

Initialize from an administrator terminal, generate a secret, display enrollment information, confirm a valid code, persist private identity data, and validate/apply baseline protection and startup integration. Secrets must not appear in logs or command-line arguments.

Do not enable default deny before confirmation. Do not reenroll an existing identity. Without enrollment or a terminal, background startup must fail with console initialization instructions instead of hanging for input.

### Separate baseline and runtime units

- `ssh-protecter-guard.service`: a oneshot baseline installer that remains active, not a second resident process.
- `ssh-protecter.service`: the long-running web/authorization service that restores and reconciles grants.

Add `Requires=` and `After=` on guard to sshd and to its socket when socket activation exists. `Before=sshd.service` alone neither starts guard nor prevents SSH startup when guard fails.

Guard uses the last successful protection configuration without depending on certificates or web readiness. A broken new certificate/configuration must not prevent baseline installation. If guard cannot install rules, prevent SSH startup and repair through the console.

Main-service restart must not restart sshd. Stopping it must not remove the protection table. Define and verify install/start/stop/uninstall effects separately.

### Health and restart

The proposal uses `Type=notify`, reporting readiness after baseline, storage, and listener readiness. Restart intervals and limits require target testing. Heartbeats depend on bounded storage, firewall, and HTTP checks rather than an unconditional timer.

On fatal faults stop granting and exit or stop heartbeats. Never recover by opening SSH. Report disk-full, database, or key-read errors while retaining existing kernel rules. Keep SELinux enabled and configure permissions from real audit evidence.

## 5. State, concurrency, and recovery

| Entity | Proposed fields |
| --- | --- |
| Verifying user | Stable ID, secret reference, enabled status |
| Temporary grant | Normalized IP, user ID, grant time, UTC Unix deadline, status/version |
| Verification failure | Normalized request source IP, event time |
| Verification-entry ban | Normalized request source IP, UTC Unix deadline |
| Configuration generation | Generation ID, effective snapshot, application status |

Serialize renewal, reload, and repair through one state coordinator so reconciliation cannot restore stale deadlines. Normalize IPv4-mapped IPv6. Count failures in a rolling window, not fixed clock-hour buckets. Persist retained events; success does not clear failures still in the window. Already banned requests must not extend a fixed ban indefinitely.

SQLite and kernel updates are not one transaction. The design proposes recoverable operation records: persist an authenticated intent with its deadline, submit kernel changes atomically, complete persistence before reporting success, and recover intermediate states after crashes. When uncertain, suspend new grants rather than widening access. The implemented flow persists grant intent before kernel application and acknowledges only after confirmation; see [firewall execution](firewall.en.md).

Failed or timed-out submissions may have effects. Recovery must test every persistence/kernel boundary and retries must have explicit deadline behavior. Machine reboot cannot preserve TCP/SSH sessions; preservation applies to expiry and gate operations only.

## 6. Configuration and reload

The original proposed shape was illustrative rather than a promise of supported fields. Use the current [direct TLS](../configs/config.example.yaml) and [proxy](../configs/nginx.example.yaml) examples for actual configuration, including clock settings.

Strictly parse individual IPs, ports, and durations. Reject unknown/duplicate fields, empty or duplicate/invalid port lists, invalid durations, and conflicting TLS/listener settings. Restrict configuration writes to root and state access to the service identity. Never expose secrets in state output. Distinguish syntax checks from privileged environment verification.

Prepare a complete new configuration, checked firewall batch, and certificates before application. Do not stop the existing listener before validation. Use transactional nft batches and serialize reloads. Cross-resource recovery must use effective snapshots and recovery records; a file rename does not commit kernel, database, and memory together.

Pre-application failures retain old state. Mid-application failures attempt rollback. If rollback cannot be confirmed, stop granting, retain the strictest recoverable baseline, and report the fault.

Duration changes affect subsequent events; existing deadlines stay fixed. Permanent allowlist changes take effect on successful reload. Listener/mode/storage changes may require offline handling and must be explicitly rejected as hot reloads rather than ignored. The implementation uses `configure` for offline listener/mode changes and rejects direct database-path changes; see [reload](reload.en.md).

Removing a port/address family reduces protection. Configuration does not modify sshd or prove it listens on a specified port.

## 7. HTTPS and source addresses

- Direct mode terminates TLS in Go, uses the network peer, and ignores client-supplied source headers.
- Proxy mode uses a loopback listener and Nginx TLS termination. The proxy overwrites source headers. Trust depends on the actual peer and explicitly configured ranges; do not unconditionally select the leftmost forwarded address.
- Keep request source and target IP separate. Failure limits always apply to the source, preventing a submitted target from shifting a ban to someone else.
- Do not create a long-lived web session exempt from TOTP. Every grant/renewal submits a code and reports the actual target and deadline.
- Use POST, bounded request bodies, same-origin/CSRF protection, and logs without codes.
- Renew certificates externally and activate them through validated reload. Reload Nginx separately in proxy mode.

Deployment examples cover TLS, loopback upstreams, overwritten headers, request limits, and renewal. SELinux, firewalld, and proxy-bypass behavior require target testing.

## 8. Time, credential recovery, and limitations

TOTP and persisted deadlines depend on correct system time. Require reliable synchronization; pause new grants on rollback or untrusted time without awarding fresh duration. The original design called for dedicated threshold and reboot-trust tests; the implemented high-water marks, synchronization checks, monotonic checks, and recovery command are documented in [operations](operations.en.md#clock-protection-across-reboots).

Code reuse within the validity window is intentional; successful time steps are not deduplicated. The proposed standard 30-second cycle and bounded tolerance must not expand automatically after failures. The implementation accepts a fixed plus/minus one-step window.

Rebinding is local-root only: verify the new authenticator, coordinate temporary-grant revocation and secret switching, invalidate the old secret, and preserve permanent entries and established sessions. Do not expose unauthenticated web rebinding.

Public-IP grants cannot distinguish devices behind one NAT. This gate does not replace SSH keys, accounts, or authentication.

## 9. Acceptance plan

Use a Rocky Linux 10 VM with console recovery. A Windows development directory cannot establish Linux firewall behavior.

1. IPv4/IPv6 default deny, manual targets, multiple ports, and permanent entries.
2. Expiry denies new connections while preserving established sessions; disconnecting does not revoke early.
3. Concurrent renewal and reconciliation preserve correct deadlines without unintended extension or shortening.
4. Rolling failures, threshold-triggered bans, and persistence across restart.
5. Crash, hang, and normal restart retain baseline rules and scheduled grant expiry.
6. Full reboot applies baseline before SSH and restores only remaining unexpired lifetimes.
7. Broken new configuration/certificates do not replace effective configuration; startup still installs baseline protection.
8. Recovery at every persistence/kernel interruption boundary; full, read-only, or corrupt storage.
9. Docker outbound traffic, published ports, Docker restart, and firewalld reload/restart.
10. Forged headers, untrusted proxies, direct upstream access, mapped IPv6, and cross-site submissions.
11. Invalid configuration, rule failure, and interrupted reload produce explainable, inspectable recovery states.
12. Rebinding revokes temporary grants while preserving permanent entries and established sessions.
13. Repair after deleted rules and actual behavior during clock jumps.

The proposed implementation order was CLI/configuration/storage, kernel/startup integration, TOTP/web, HTTPS/Nginx, then fault acceptance. Current implementation and remaining verification are described in the operational guides.

## 10. References

- [nftables objects, checking, and set timeouts](https://www.netfilter.org/projects/nftables/manpage.html)
- [nftables chains and verdicts](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- [Docker firewall packet paths](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker nftables backend and accept/drop behavior](https://docs.docker.com/engine/network/firewall-nftables/)
- [firewalld nftables table isolation](https://firewalld.org/2018/07/nftables-backend)
- [RHEL 10 nftables guidance as a related-platform reference](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_firewalls_and_packet_filters/getting-started-with-nftables)
- [systemd notifications, restart, and watchdog](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [systemd dependencies and ordering](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- [SQLite atomic commit and boundaries](https://www.sqlite.org/atomiccommit.html)
- [TOTP specification](https://www.rfc-editor.org/rfc/rfc6238.html); this project intentionally permits reuse of codes within their acceptance window.
