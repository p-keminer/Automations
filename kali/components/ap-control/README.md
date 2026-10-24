# Control WLAN visibility

Optional component for the accepted Kali Pi4 builder network layout. Install
alongside `auto-cli`, which dispatches `auto ap` and loads its completion list.
Selecting or installing this component does not change the AP configuration or
restart a service.

```text
sudo auto ap --status
sudo auto ap --invisible
sudo auto ap --visible
auto ap --help
```

No argument means `--status`. Status is read-only and separates configured
visibility from the live AP/interface state. It explicitly does not independently
verify transmitted beacons. Help needs no root or system files; configuration is
root-readable on the standard image, so use `sudo` for status and changes.

## Applying a change

`--visible` and `--invisible` schedule a short, independent root systemd worker.
The worker saves only `ignore_broadcast_ssid` in `/etc/hostapd/hostapd.conf` and
restarts **only hostapd** to apply the setting immediately. The control WLAN and
browser/SSH transport disconnect briefly; reconnect to the same network, then
run `sudo auto ap --status`. Guacamole services, session processes, passwords,
client ACLs and network ownership are not changed. This does not promise an
uninterrupted transport or a fixed reconnection delay.

The setting persists across reboot. Hiding the SSID suppresses normal name
advertisement; it adds no access security. A new client may need the exact network
name entered manually. Even requesting the already configured value deliberately
restarts hostapd: a saved value alone cannot prove that the firmware applied it.

The calling command reports **scheduled**, not completion. A successful scheduling
exit code does not prove successful application. `--status` shows the last worker
result: `queued`, `running`, `applied`, `recovered` or `failed`. `applied` means a
verified new hostapd process is ENABLED on ctrl0 with its expected address and
configuration; it is not a passive radio measurement. `recovered` reports whether
the previous configuration was restored or no worker change was made. A failed
recovery requires administrator inspection.

## Scope and recovery

Only the known single-BSS Kali builder configuration, ctrl0 naming rule and
NetworkManager exclusion are supported. The current daemon command and the next
loaded start definition are checked: exact service/drop-in, environment file,
effective command/environment, no pending daemon reload and no unknown Exec
hooks. Unknown, unsafe or externally changed configuration is refused.

The worker is the fixed transient `automations-ap-apply.service`, using the
trusted installed AP executable through isolated Python. One private root-owned
record under `/run/automations-ap` and the existing AP lock coordinate callers.
No arbitrary job commands, paths, environment or production test-root override
are accepted. A concurrent operation is rejected; disconnecting the caller does
not terminate the worker. Commands and readiness polls have bounded timeouts.

Writes use a same-directory temporary file, preserved owner/mode, fsync and
atomic rename, with content/metadata checked again immediately before replacement.
Only an exact owned systemd restart job may be cancelled. The `fail` job mode
refuses a conflicting job instead of replacing it. On failure the worker settles
the job, restores only its own unchanged replacement, and attempts to restart
the previous supported configuration. External edits are neither overwritten nor
deliberately restarted. ExecStopPost handles incomplete worker recovery; completed
records do not cause another restart. Credentials/ACL files are not read.

Power loss or forcibly killing recovery is not fully transactional. Killing the
caller between recording and submitting the worker can leave a blocked queued
record without changing hostapd. Such unfinished operations require inspection;
do not delete the private record or edit hostapd concurrently while an operation
is active. Normal status must never claim recovery or radio success without its
respective evidence.

Exit codes: `0` observation or successful scheduling, `1` unsafe/unavailable
platform or operation failure, `64` invalid arguments, `77` changes without root,
`130` interrupted caller. An absent/disabled AP can be reported by status; change
commands do not create or start it.

## Verification

Run `python3 tools/components.py check --component ap-control`. Tests use temporary
fixtures and a simulated command runner. They cover public options, native
systemd 262 definition observations, future-start guards, actual versus saved
state, fixed worker trust, job races, duplicate requests, equal-config firmware
drift, new-PID readiness, CAS writes, interruption and recovery, external edits,
permissions and secret suppression. No Pi or network command is executed.

The earlier SET/UPDATE_BEACON implementation returned success and preserved AP
connectivity, but an independent own-BSSID capture on 2026-10-19 still observed
the name `Pi4` after requesting hidden mode. The pinned brcmfmac implementation
updates firmware `closednet` during AP start, while change-beacon updates only
extra management IEs. Those earlier checks were therefore not evidence of hidden
beacons. Version 0.1.2 replaces that path with the bounded restart worker.

The new worker passed offline review/fixtures. Live visible/hidden/visible beacon
acceptance, reconnection and separate Guacamole/session continuity checks remain
required; no new hardware success is claimed here.

Primary references:

- [Raspberry Pi brcmfmac AP start/change-beacon implementation](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.12.y/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c).
- [systemd transient service lifecycle](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
- [systemd D-Bus job and service properties](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).