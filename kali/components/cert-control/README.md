# Certificate download control

Optional `auto cert` command for the accepted Pi4 nginx layout.
Requires the optional `auto-cli` dispatcher component alongside this component.
The manifest format currently has no component-dependency field; select both.

```sh
auto cert                  # same as --status
auto cert --status
sudo auto cert --off
sudo auto cert --on
auto cert --help
```

All command output and help are English. Bash completion data lists the four
supported options. Help and status do not require root, although status needs
permission to read the nginx configuration and query systemd.

Only these exact public CA download locations are changed:

- HTTP `/cert`
- HTTP `/pi4-ca.crt`
- HTTPS `/cert`

`--off` replaces their download directives with `return 404;`.
`--on` restores the known public `/etc/pi4/tls/ca.crt` download directives.
It never changes certificate files, TLS keys, firewall rules, remote sessions,
Guacamole proxy locations, other nginx routes, or service enablement. nginx is
not stopped or started. Disabling downloads does not invalidate certificates
already installed on client devices.

The fixed configuration path is `/etc/nginx/conf.d/pi4-remote.conf`.
The command accepts only the two known v05 listeners and the three recognized
download blocks. Duplicate, missing or customized download blocks are rejected.
A mixed on/off configuration may be normalized to the requested state.
There is no CLI path override or arbitrary nginx command execution.

Changes use an exclusive lock, an atomic file replacement, preserved owner/group
and mode, and nginx syntax validation before reload. Both the original and the
candidate configuration must validate. On candidate validation failure the
original bytes are restored. A failed reload also triggers restoration and a
reload of the original configuration. Any unsuccessful rollback is reported
explicitly. Concurrent edits detected during replacement are not overwritten.
An already configured state causes no write and no unnecessary reload.

If nginx is inactive or failed, a valid change is saved for its next start;
the service is not started automatically. Transitional states are rejected.
`--status` reports the configured on/off/mixed state and the actual systemd
service state separately. It does not claim that the file matches nginx's
currently loaded routes; no HTTP/HTTPS route probe is performed. An unrelated
manual edit or reload outside this command can therefore require operator
verification. The transaction protects concurrent `auto cert` invocations,
not every external administrator/editor.

Exit status: 0 = success/status, 1 = operation/configuration failure,
2 = invalid command arguments.

## Local checks

```sh
python3 tools/components.py check --component cert-control
```

Tests use temporary configurations and fake service commands. They cover route
scope, preservation of unrelated content and permissions, malformed input,
idempotence, inactive service handling, rollback, concurrent edits, locking,
and CLI permissions. They do not restart nginx, modify the Pi, or replace a
hardware test with the actual installed nginx version.

The component is optional and defaults to unselected. Installation alone does
not change download availability. No image rebuild, archive publication, or
live Pi modification is part of preparing this component.


## Pi4 hardware verification — 2026-10-19

On the running v05 Pi, HTTP `/cert`, HTTP `/pi4-ca.crt`, and HTTPS
`/cert` each returned 200 → 404 → 200 for on → off → on. The checks allowed
a bounded wait for nginx's graceful worker reload. The CA download SHA-256
was identical before and after; the original nginx configuration hash was
also restored exactly.

HTTPS `/remote/` remained reachable with status 200 while certificate downloads
were off. All six monitored service main PIDs remained unchanged, and repeating
`--off` performed no additional change. The local evidence is
`basic-controls-cert-hardware.json`. This test did not reboot the Pi or exercise
a new browser interaction.
