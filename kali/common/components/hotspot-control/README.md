<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Zusätzlicher USB-AP mit Willkommensseite

`sudo auto share ap "SSID" [--interface IFACE] [--template NAME]` startet einen
optionalen, nur zur Laufzeit bestehenden AP auf einem der externen USB-Adapter
oder benennt ihn um. Beide Adapter bleiben austauschbar; keiner ist für den AP
reserviert. Der interne AP `ctrl0` bleibt unverändert. `auto ap` steuert weiterhin
nur Sichtbarkeit und Status dieses Steuer-WLANs.

Bei mehreren Kandidaten fragt ein echtes Terminal nach Interfacenummer oder -name.
Automatisierte Aufrufe müssen `--interface` angeben. Eine getrennte verdeckte
Passwortabfrage akzeptiert eine leere Eingabe für einen offenen AP oder 8–63
druckbare ASCII-Zeichen für WPA2. Es gibt keine willkürlichen Komplexitätsregeln.
SSIDs dürfen 1–32 UTF-8-Bytes lang sein. Clientprofile und ihre Autoconnect-Flags je
SSID bleiben erhalten. Während des AP-Betriebs verlässt der ausgewählte Adapter
sein bisheriges Clientnetz. Beim Stoppen kehrt er in den getrennten Managed-Modus
zurück. Es entsteht weder ein AP-Profil noch ein für den Boot aktivierter Dienst.
Der AP-Worker prüft während des Betriebs die gespeicherte PHY- und Namespace-
Interfaceidentität. Verschwindet der Adapter, wird der AP gestoppt und bereinigt,
auch wenn hostapd noch ENABLED meldet. Erneutes Einstecken startet den AP nicht
automatisch; er muss ausdrücklich neu gestartet werden. Ein anderes Interface mit
demselben Namen wird nicht verändert.

Befehle:

```sh
sudo auto share ap "Welcome" --interface wlan1 --template welcome
sudo auto share ap --status
sudo auto share ap "New name" --interface wlan1
sudo auto share ap --off
sudo auto share ap --help
sudo auto share --wifi --to wlan0 --from wlan1
sudo auto share --wifi --to wlan0 --from ctrl0,wlan1
sudo auto share --off
```

Der AP verwendet einen eigenen Netzwerk-Namespace, hostapd, DNS/DHCP und einen
statischen Webserver. AP-Clients erreichen nur HTTP/HTTPS und die erforderlichen
DHCP-/DNS-Dienste. Es gibt weder SSH, Guacamole, einen Verwaltungsendpunkt noch
einen Weg zum Steuer-WLAN oder zu privaten Upstream-Netzen. Client-Isolation ist
aktiviert. IPv6 ist auf diesem zusätzlichen AP deaktiviert; das Steuer-WLAN behält
sein normales IPv6-Verhalten.

Internetzugriff bleibt aus, bis `auto share --wifi/--lan` aktiviert wird. `--to`
wählt den Ausgang; `--from` wählt die Clientnetze mit Internetzugang, durch Kommas
getrennt. Ohne `--from` erscheint eine nummerierte Auswahl mit Interfacenamen und
SSIDs. Der Pi und die gewählten Clientnetze nutzen diesen Uplink ohne Ausweichweg.
Share OFF entfernt die Weiterleitung, lässt die lokale Willkommensseite aber
erreichbar. Tor übernimmt den gewählten Uplink und wendet seine üblichen TCP-/DNS-
Grenzen auch auf AP-Clients an. Vor Änderungen an AP-Topologie oder Uplink Tor ausschalten.

Portalvorlagen liegen unter `/usr/local/share/automations/hotspot/templates/NAME/`.
Jede enthält `index.html` und optional lokale CSS-, JavaScript-, Bild- und
Schriftdateien. `--template NAME` wählt den Verzeichnisnamen. Ohne diese Angabe
listet ein Terminal die verfügbaren Vorlagen und fragt nach Nummer oder Name.
Nichtinteraktive Aufrufe müssen den Namen angeben. `{{SSID}}` ist optional und wird
HTML-escaped eingesetzt. Die Vorlagen bleiben installiert; bei jedem AP-Start
wird eine Momentaufnahme der ausgewählten Dateien erstellt. Vorlagen mit sudo
bearbeiten/ergänzen. `--status` zeigt den gewählten Namen sowie Vorlagen- und
Laufzeitverzeichnisse. Auf einem portablen Kali-Host liefert ein eigener temporärer
Webdienst HTTP an derselben Adresse aus; Pi4 behält seinen isolierten nginx-Dienst.
Das Steuer-WLAN liefert weiterhin Guacamole aus.

HTTP `http://10.79.0.1/` ist der Portaleinstieg. HTTPS `https://pi4/` verwendet das
bestehende Pi4-Zertifikat und benötigt deshalb das vorhandene Vertrauen in die
Pi4-CA. HTTPS-Anfragen an fremde Domains werden weder nachgeahmt noch abgefangen.
Das Betriebssystem entscheidet, ob es sein Captive-Portal-Fenster öffnet. Wenn
kein Fenster erscheint, die HTTP-Adresse direkt öffnen. Übliche Hostnamen für
Verbindungsprüfungen führen zum Portal.

Vor einer Adapteränderung werden das feste zusätzliche Subnetz und die
Transitverbindung auf Konflikte geprüft. Ein fehlgeschlagener Start versucht, die
vorherige Clientverbindung wiederherzustellen. Ein Dienstfehler stoppt die
Namespace-Dienste. Kein Dienst wird für den Boot aktiviert; der gesamte aktive
AP-Zustand liegt unter `/run`.

Hardwareabnahme ist von isolierten Tests getrennt: AP-Unterstützung, Anmeldung,
Client-Isolation, Captive-Fenster und USB-Abziehen/Wiedereinstecken müssen an
echten Adaptern und Endgeräten geprüft werden.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Additional USB welcome AP

`sudo auto share ap "SSID" [--interface IFACE] [--template NAME]` starts or renames one optional,
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
sudo auto share ap "Welcome" --interface wlan1 --template welcome
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

Portal templates live in `/usr/local/share/automations/hotspot/templates/NAME/`;
each contains `index.html` and may include local CSS, JavaScript, images and fonts.
Select the directory name with `--template NAME`; without it, a terminal lists the
available templates and asks for a number or name. Non-interactive calls must
supply the name. `{{SSID}}` is optional and HTML escaped. Templates stay installed;
the chosen files are snapshotted for each AP start. Edit/add templates with sudo.
`--status` shows the selected name and template/runtime directories. The portable
Kali host serves HTTP at the same address using its own temporary web service;
Pi4 keeps its isolated nginx service. The control WLAN continues serving Guacamole.

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

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
