# SSH access gate

[English](CONTEXT.en.md) | [简体中文](CONTEXT.md)

Source-IP authorization for new SSH connections. SSH's own authentication remains independent.

## Language

**Verifying user**: A person holding the enrolled authenticator who can request access through the web page. The first version supports one verifying user.

**Request source IP**: The actual client address of the web request, as reported by an explicitly trusted proxy when applicable. Failure counting and verification-entry bans apply to this address.
_Avoid_: Target IP.

**Target IP**: The address for which SSH access is requested. It defaults to the request source IP and may be entered manually.

**Temporary grant**: Permission for an IP to establish new SSH connections before a specified deadline. Successful verification updates the deadline. Disconnecting does not end the grant early.
_Avoid_: SSH session; code validity period.

**Permanent allowlist**: Configured IP addresses that can connect without a temporary grant. This does not bypass SSH authentication or verification failure limits on the web page.

**Verification-entry ban**: A temporary block on authorization requests from a request source IP after excessive verification failures. Its policy is independent of the permanent SSH allowlist.

**Established-connection preservation**: Grant expiry, reloads, and gate restarts do not actively disconnect established SSH connections. A whole-machine reboot cannot preserve those connections.

**Trusted proxy**: An administrator-designated proxy allowed to report web client addresses. Trust is established from the actual connection peer.

**Default deny**: IP addresses without a permanent allowlist entry or an unexpired temporary grant cannot establish new connections to protected SSH ports. Established connections follow the preservation policy.
