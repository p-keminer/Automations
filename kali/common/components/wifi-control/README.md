# External USB Wi-Fi control

`auto wifi` command for the Pi4 control-network layout. Install together with
`auto-cli`. Version0.1.5 supplies an event-driven saved-profile policy service;
the Builder enables it before NetworkManager. The policy normalizes unapproved
saved client profiles to manual without disconnecting an active connection.
It does not activate a WLAN or enter monitor mode.

```sh
auto wifi --status
sudo auto wifi "My SSID"
sudo auto wifi "My SSID" --autoconnect-on
sudo auto wifi "My SSID" --autoconnect-off
sudo auto wifi --off
sudo auto wifi --monitor
sudo auto wifi --managed
sudo auto wifi --interface wlan0 "My SSID"
auto wifi --help
```

All CLI output is English. German and English short reference files are included
under `/usr/local/share/automations/help/docs/{de,en}/wifi-control.txt`.
Bash option completion is supplied as data, without running the module.

## Interface protection and selection

Discovery uses sysfs USB ancestry, wireless PHY identity and interface indexes;
it does not depend on an ALFA brand, driver name or a fixed `wlan0` name.
Only USB Wi-Fi adapters can be selected. The known `ctrl0` interface must exist
and be identifiable. It and every interface sharing its physical radio are
excluded, even with an explicit `--interface` argument.

If exactly one external interface is available, it is selected automatically.
If several exist, a real terminal lists their names/USB identities and asks for
one number or name. Without a TTY, modifying operations require `--interface IFACE`.
No eligible adapter produces an error. Status lists all eligible interfaces
unless one is selected explicitly.

Before every mutating command, sysfs and `iw` identities are checked again.
A replacement device with the same name is not used for rollback. An external
radio with multiple interfaces is readable in status but cannot be changed:
this prevents a mode switch from disrupting a sibling interface.
There is no global radio toggle, driver unload, interface deletion,
`airmon-ng`, firewall modification or control-network ownership change.

## Connecting and stored credentials

The script requests a fresh scan on the selected external interface, then uses
NetworkManager's native `device wifi connect` operation. NetworkManager selects
a compatible existing profile and its saved credentials when available, or
creates a profile for a new WLAN. A different current WLAN is switched on the
same selected adapter.

With a terminal attached, the native `nmcli --ask` secret agent performs a
hidden password prompt only when credentials are needed. Existing usable
credentials do not require another password. An incorrect or expired saved
credential may require re-entry. The script never reads PSKs, opens NM keyfiles,
uses `--show-secrets`, accepts a password option, or puts passwords in arguments,
logs or temporary files. NetworkManager stores credentials according to the
profile's normal secret policy.

Without a terminal, saved credentials may still work, but the script does not
accept plaintext password input from redirected stdin. Run interactively if
credentials are missing. Native activation errors remain errors; a successful
activation is checked against the actual active profile SSID.

SSID arguments must contain 1–32 UTF-8 bytes and no control characters.
A MAC-shaped name such as `00:11:22:33:44:55` is rejected because nmcli would
interpret it as a BSSID. Use `--` before an SSID beginning with `--`.
New hidden-SSID setup and new enterprise/802.1X profile configuration are outside
this initial command's scope; existing compatible enterprise profiles remain
managed by NetworkManager.

This command uses ordinary NetworkManager routing. It does **not** guarantee
that every outgoing connection uses the USB adapter; exclusive routing is a
separate planned component.

## Persistent autoconnect for a saved WLAN

Two targeted Pi reboots on23October2026 verified the defaults and explicit
opt-in: with an empty approval list, both USB WLAN adapters stayed disconnected;
with only the existing guest UUID approved, that profile connected automatically
after boot and the other three stayed manual. The policy was ready before NM
on both boots. All four original profiles and saved credentials were preserved.
The final setting was restored to all-manual while retaining the active guest
connection. See the Builder evidence `ssh-wifi-postimplementation-review-20261023.json`.
Enabling autoconnect can cause NetworkManager to connect a currently disconnected
eligible device immediately; the CLI does not issue a separate activation request.

Saved client WLANs now default to manual connection, including new desktop
profiles. The event-driven automations-wifi-policy.service disables autoconnect
on unapproved saved client profiles using non-secret D-Bus metadata and native
property-only updates. It does not poll, reconnect, reapply or reset adapters.
Before NetworkManager starts, its preparation changes only the connection
autoconnect line in unapproved keyfiles, preserving all other bytes. Ethernet,
AP, temporary/generated and protected ctrl0 profiles are excluded.

--autoconnect-on records an explicit UUID opt-in in the root-owned
/var/lib/automations-wifi/autoconnect.json and enables the profile bit;
--autoconnect-off removes it and disables the bit. Credentials remain unchanged,
and neither operation creates a profile. Manual connect retains an existing
opt-in, otherwise leaves that profile's autoconnect off. A copy with a new UUID
has no approval. NewConnection/Updated correction from desktop creation is
asynchronous; this is profile policy, not a barrier against a privileged client
racing or disabling the service.

`sudo auto wifi "My SSID" --autoconnect-on` and `--autoconnect-off` change
`connection.autoconnect` and its UUID opt-in record in one existing saved client profile. The change
persists across reboot. They require an SSID and an eligible selected USB adapter;
with several adapters, add `--interface IFACE`. No new profile is created.
Only profiles in `/etc/NetworkManager/system-connections` with D-Bus `Unsaved=false`
and `Flags=0` qualify. Runtime-only, unsaved, generated and vendor profiles are
rejected, including an otherwise idempotent request. The `busctl` reads supplied
by systemd fetch only these metadata properties; no keyfile or secret is read.
Plain `auto wifi "My SSID"` keeps its existing connect/switch behavior.

The SSID is read exactly, separately from other fields. Profile changes use its
UUID, never the displayed connection name. Multiple compatible profiles with the
same SSID are rejected even when one is currently active. AP/ad-hoc profiles,
profiles bound to another interface, controller/bridge-port profiles, and profiles
with advanced `match.*` constraints are excluded. MAC-bound matching profiles are
rejected because the installed NetworkManager does not expose the permanent MAC
through the checked field; the current, potentially randomized MAC is not trusted.
A profile currently used by ctrl0 or another interface on its radio is protected.

These operations issue no connect/disconnect, scan, mode change or device
`autoconnect` update. NetworkManager may itself activate an enabled profile when
its normal conditions allow it. `--autoconnect-off` does not disconnect an active
connection. `--autoconnect-on` does not clear the device-level block left by
`auto wifi --off`; profile permission and device runtime permission are separate.
A manual connection still works as before and preserves that runtime flag.

The selected profile is rechecked before the write and verified afterwards.
On failure or interruption only this profile's old autoconnect bit is restored,
provided its identity/binding metadata remains unchanged. A removed or independently
changed profile is not recreated or overwritten; incomplete restoration is reported.
The command lock serializes this tool, not independent NetworkManager clients.

## Off and operating modes

`--off` in client mode disconnects only the selected device and disables its
runtime autoconnect. Saved profiles and keys remain intact. Repeating it is
safe. This is not a persistent radio ban: reboot, hotplug or an explicit
connection request can change the runtime state.

`--monitor` verifies driver support, disconnects the selected client,
releases that device from NetworkManager, and changes the existing interface
to monitor mode with `iw`. It does not create/delete interfaces or alter the
regulatory domain, channel configuration or other adapters. Only normal
client/monitor transitions are supported.

`--managed` returns a monitor adapter to client mode and NetworkManager
ownership, initially disconnected with runtime autoconnect disabled.
**If already in managed mode under NetworkManager, an existing connection is
left unchanged.** Explicit `--managed` can also reclaim a client interface
that was unmanaged; other interface modes such as AP are rejected.

In monitor mode `--off` brings down only that selected link; it does not change
its mode. A later `--monitor` raises it again. Mode changes are runtime changes,
not a boot service or permanent driver configuration.

Operations are serialized. Failed connection or mode changes, including an
interrupt, attempt to restore the original device mode, administrative link
state, NetworkManager ownership/autoconnect and previous active profile UUID.
The old connection is reactivated using its saved credentials without a new
password prompt. Saved profiles are never deleted. A disappeared adapter,
changed hardware identity, unavailable old WLAN or failed native command can
prevent complete restoration; this is reported explicitly instead of claiming
success. The script cannot undo independent changes made concurrently by
another administrator or service.

## Status and exit codes

Status reads the current physical interface, mode, administrative and kernel
operational link states separately,
NetworkManager ownership/state/autoconnect, active profile SSID and UUID, and
IPv4/IPv6 addresses. It performs no connect, scan or mode change.
`admin up` means the interface is enabled, not that Wi-Fi is connected.
`operational unknown` is retained when the driver does not report a link state,
including some monitor-mode interfaces; it is not inferred as up or down.
Help and status are unprivileged; mutations require root.

Exit 0 indicates success; 1 indicates a configuration/native-operation error;
2 indicates invalid CLI arguments. An interrupt outside a transaction returns
130. An interrupted transaction that reports its rollback result returns 1.

## Verification

```sh
python3 tools/components.py check --component wifi-control
```

The standalone fixture suite covers USB and whole-PHY exclusion, absent and
multiple adapters, changed hardware identities, native profile reuse without
secret arguments, switching and rollback, hidden-agent invocation, client/
monitor transitions, unsupported drivers, idempotent off, lock behavior,
permissions, status and CLI validation. Version 0.1.2 adds profile-only persistence,
exact SSID/UUID matching, ambiguity and protected/foreign-profile rejection,
unchanged device commands, idempotence, partial-write/readback/interruption rollback,
deleted/concurrently changed profiles, persistent-storage guards, option validation and direct executable help.
The new profile switches are fixture-tested; live acceptance is still pending.

Native read-only field formats were checked against the v05 Pi's
NetworkManager 1.56.1 and installed `iw`/`ip`. Actual connection/password reuse,
external WLAN switching, disconnect, monitor/managed switching and physical
rollback remain for the joint hardware test. Fixture success is not a hardware
acceptance result. No image rebuild or live mode/connection change is part of
preparing this component.

Primary references:
[NetworkManager profile autoconnect](https://networkmanager.dev/docs/api/latest/settings-connection.html),
[NetworkManager nmcli manual](https://networkmanager.dev/docs/api/latest/nmcli.html),
[NetworkManager 1.56.1 native Wi-Fi connection implementation](https://github.com/NetworkManager/NetworkManager/blob/1.56.1/src/nmcli/devices.c),
[Linux Wireless iw documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html).
