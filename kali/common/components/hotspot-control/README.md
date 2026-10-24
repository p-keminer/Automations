# Additional USB welcome AP

`sudo auto share ap "SSID" [--interface IFACE]` starts or renames one optional,
runtime-only AP on either external USB adapter. Both adapters remain interchangeable:
neither is reserved for AP use. It never changes the internal `ctrl0` AP;
`auto ap` continues to control only the visibility/status of that control WLAN.

With multiple candidates, a real terminal asks for an interface number or name.
Automation must supply `--interface`. A separate hidden password prompt accepts
an empty value for an open AP, or 8–63 printable ASCII characters for WPA2.
No arbitrary complexity rules. SSIDs support 1–32 UTF-8 bytes. Client profiles
and their per-SSID autoconnect flags are retained. The selected adapter leaves
its current client network while the AP runs. Stopping returns it to managed,
disconnected mode. No AP profile or enabled boot service is created.
The AP worker checks the recorded PHY and namespace interface identity while
running. Losing the adapter stops and cleans up the AP even if hostapd still
reports ENABLED. Reconnecting a USB adapter does not restart the AP automatically;
start it again explicitly. A different interface reusing the name is not changed.

Commands:

```sh
sudo auto share ap "Welcome" --interface wlan1
sudo auto share ap --status
sudo auto share ap "New name" --interface wlan1
sudo auto share ap --off
sudo auto share ap --help
sudo auto share --wifi --to wlan0 --from wlan1
sudo auto share --wifi --to wlan0 --from ctrl0,wlan1
sudo auto share --off
```

The AP uses its own network namespace, hostapd, DNS/DHCP and static web server.
Only HTTP/HTTPS and the essential DHCP/DNS services are exposed to AP clients.
There is no SSH, Guacamole, administration endpoint or route to the control or
private upstream networks. Station isolation is enabled. IPv6 on this additional
AP is disabled; the existing control WLAN keeps its normal IPv6 behavior.

Internet access is off until normal `auto share --wifi/--lan` is enabled.
`--to` selects its output; `--from` selects client networks receiving
Internet, comma-separated. Omit `--from` to choose from a numbered list with
interface names and SSIDs. The Pi and selected client networks use that uplink, with no
fallback. Share OFF removes forwarding but leaves the local welcome page up.
Tor inherits the selected uplink and applies its normal TCP/DNS restrictions to
AP clients too. Turn Tor off before changing AP topology or the selected uplink.

The editable UTF-8 template is `/usr/local/share/automations/hotspot/welcome.html`.
`--status` shows this template directory and `/run/automations-hotspot-www`,
the directory of generated files currently served by nginx. Both paths are
reported even while the AP is off; the runtime directory then does not exist.
`{{SSID}}` is HTML escaped before substitution; restart/rename the AP to apply
template changes. No external assets, input forms, telemetry or credentials.
HTTP `http://10.79.0.1/` is the portal entry. HTTPS `https://pi4/` uses the existing
Pi4 certificate, and therefore needs the existing Pi4 CA trust. HTTPS requests
to unrelated domains are never impersonated or intercepted. Operating systems
decide whether to show their captive-portal window; if no window appears, open
the HTTP address directly. Common connectivity-check hostnames reach the portal.

The fixed additional subnet and transit link are checked for conflicts before
changing any adapter. A failed start attempts to restore the previous client
connection. A service failure stops its namespace services; no service is
enabled at boot, and all active AP state lives under `/run`.

Hardware acceptance is separate from isolated tests: AP support, association,
client-to-client isolation, captive-window behavior and USB unplug/replug must
be checked on actual adapters/devices.
