<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Externes USB-WLAN steuern

Befehl `auto wifi` für das Pi4-Steuernetzlayout. Zusammen mit `auto-cli` installieren.
Version 0.1.5 stellt einen ereignisgesteuerten Richtliniendienst für gespeicherte
Profile bereit; der Builder aktiviert ihn vor NetworkManager. Er setzt nicht
freigegebene gespeicherte Clientprofile auf manuelle Verbindung, ohne eine aktive
Verbindung zu trennen. Er aktiviert weder ein WLAN noch den Monitor-Modus.

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

Alle CLI-Ausgaben sind Englisch. Deutsche und englische Kurzreferenzen liegen unter
`/usr/local/share/automations/help/docs/{de,en}/wifi-control.txt`.
Die Bash-Optionsvervollständigung wird als Daten geliefert, ohne das Modul auszuführen.

## Schutz und Auswahl der Schnittstelle

Die Erkennung nutzt die USB-Abstammung in sysfs, die WLAN-PHY-Identität und
Interfaceindizes. Sie hängt weder von der Marke ALFA noch vom Treibernamen oder
einem festen Namen `wlan0` ab. Auswählbar sind nur USB-WLAN-Adapter. Das bekannte
Interface `ctrl0` muss existieren und identifizierbar sein. Es und alle Interfaces
derselben Funkhardware sind ausgeschlossen, auch bei explizitem `--interface`.

Bei genau einem externen Interface wird es automatisch gewählt. Bei mehreren
listet ein echtes Terminal Namen und USB-Identitäten und fragt nach Nummer oder
Name. Ohne TTY benötigen verändernde Operationen `--interface IFACE`. Kein
geeigneter Adapter führt zu einem Fehler. Status listet alle geeigneten
Interfaces, sofern keines ausdrücklich ausgewählt wurde.

Vor jedem verändernden Befehl werden sysfs- und `iw`-Identitäten erneut geprüft.
Ein Ersatzgerät mit gleichem Namen wird nicht zur Wiederherstellung verwendet.
Eine externe Funkhardware mit mehreren Interfaces kann im Status gelesen, aber
nicht verändert werden. Dadurch stört ein Moduswechsel kein benachbartes Interface.
Es gibt keinen globalen Funkschalter, kein Treiberentladen, keine Interfacelöschung,
kein `airmon-ng`, keine Firewalländerung und keinen Zuständigkeitswechsel im Steuernetz.

## Verbinden und gespeicherte Zugangsdaten

Das Skript fordert einen frischen Scan auf dem ausgewählten externen Interface an
und nutzt anschließend NetworkManagers natives `device wifi connect`.
NetworkManager wählt, wenn vorhanden, ein kompatibles Profil mit gespeicherten
Zugangsdaten oder erzeugt für ein neues WLAN ein Profil. Ein anderes aktuell
verbundenes WLAN wird auf demselben ausgewählten Adapter gewechselt.

Mit angeschlossenem Terminal übernimmt der native Secret-Agent `nmcli --ask` eine
verdeckte Passwortabfrage, ausschließlich wenn Zugangsdaten benötigt werden.
Vorhandene nutzbare Zugangsdaten benötigen keine erneute Eingabe. Falsche oder
abgelaufene gespeicherte Daten können eine neue Eingabe erfordern. Das Skript liest
keine PSKs, öffnet keine NM-Keyfiles, verwendet kein `--show-secrets`, akzeptiert
keine Passwortoption und legt keine Passwörter in Argumenten, Logs oder temporären
Dateien ab. NetworkManager speichert sie gemäß der normalen Secret-Richtlinie des Profils.

Ohne Terminal können gespeicherte Zugangsdaten funktionieren; Klartextpasswörter
aus umgeleitetem stdin werden jedoch nicht akzeptiert. Bei fehlenden Zugangsdaten
interaktiv ausführen. Native Aktivierungsfehler bleiben Fehler; nach erfolgreicher
Aktivierung wird die SSID des tatsächlich aktiven Profils geprüft.

SSID-Argumente müssen 1–32 UTF-8-Bytes lang sein und dürfen keine Steuerzeichen
enthalten. Ein Name im MAC-Format wie `00:11:22:33:44:55` wird abgewiesen, weil nmcli
ihn als BSSID interpretieren würde. Vor einer mit `--` beginnenden SSID `--`
verwenden. Die Neueinrichtung versteckter SSIDs und neuer Enterprise-/802.1X-Profile
gehört nicht zum Umfang dieses ersten Befehls; vorhandene kompatible
Enterpriseprofile bleiben unter NetworkManager-Verwaltung.

Dieser Befehl nutzt das normale NetworkManager-Routing. Er garantiert **nicht**,
dass jede ausgehende Verbindung den USB-Adapter verwendet; exklusives Routing wird
separat von `auto share` bereitgestellt.

## Dauerhaftes Autoconnect für ein gespeichertes WLAN

Zwei gezielte Pi-Neustarts am 23.10.2026 prüften Standardverhalten und ausdrückliche
Freigabe: Bei leerer Freigabeliste blieben beide USB-WLAN-Adapter getrennt; bei
Freigabe ausschließlich der vorhandenen Gast-UUID verband sich dieses Profil nach
dem Boot automatisch, während die anderen drei manuell blieben. Die Richtlinie
war bei beiden Boots vor NM bereit. Alle vier Originalprofile und gespeicherten
Zugangsdaten blieben erhalten. Abschließend wurden alle Profile wieder auf manuell
gesetzt, während die aktive Gastverbindung erhalten blieb. Siehe Builder-Nachweis
`ssh-wifi-postimplementation-review-20261023.json`. Das Aktivieren von Autoconnect
kann NetworkManager veranlassen, ein derzeit getrenntes geeignetes Gerät sofort
zu verbinden; die CLI stellt keinen zusätzlichen Aktivierungsauftrag.

Gespeicherte Client-WLANs verlangen standardmäßig manuelle Verbindung, auch neue
Desktopprofile. Der ereignisgesteuerte Dienst automations-wifi-policy.service
deaktiviert Autoconnect in nicht freigegebenen Clientprofilen über nicht geheime
D-Bus-Metadaten und native reine Eigenschaftsänderungen. Er fragt nicht fortlaufend
ab, verbindet nicht neu, wendet keine Verbindung erneut an und setzt keine Adapter
zurück. Vor NetworkManagers Start ändert seine Vorbereitung in nicht freigegebenen
Keyfiles nur die Autoconnect-Zeile und erhält alle anderen Bytes. Ethernet-, AP-,
temporäre/generierte und geschützte ctrl0-Profile sind ausgenommen.

--autoconnect-on speichert die ausdrückliche UUID-Freigabe in der Root gehörenden
/var/lib/automations-wifi/autoconnect.json und aktiviert das Profilbit;
--autoconnect-off entfernt die Freigabe und deaktiviert es. Zugangsdaten bleiben
unverändert; keine der Operationen erzeugt ein Profil. Manuelles Verbinden erhält
eine vorhandene Freigabe, andernfalls bleibt Autoconnect im Profil aus. Eine Kopie
mit neuer UUID ist nicht freigegeben. NewConnection-/Updated-Korrekturen nach
Desktop-Erstellung laufen asynchron. Dies ist eine Profilrichtlinie, keine Barriere
gegen einen privilegierten Client, der damit konkurriert oder den Dienst deaktiviert.

`sudo auto wifi "My SSID" --autoconnect-on` und `--autoconnect-off` ändern
`connection.autoconnect` und dessen UUID-Freigabe für ein vorhandenes gespeichertes
Clientprofil. Die Änderung übersteht Neustarts. Nötig sind eine SSID und ein
ausgewählter geeigneter USB-Adapter; bei mehreren `--interface IFACE` ergänzen.
Es entsteht kein neues Profil. Nur Profile unter `/etc/NetworkManager/system-connections`
mit D-Bus `Unsaved=false` und `Flags=0` sind zulässig. Flüchtige, ungespeicherte,
generierte und Herstellerprofile werden auch bei ansonsten idempotenten Anfragen
abgewiesen. Die systemd-`busctl`-Abfragen lesen ausschließlich diese Metadaten,
keine Keyfiles oder Geheimnisse. Einfaches `auto wifi "My SSID"` behält sein
bisheriges Verbindungs-/Wechselverhalten.

Die SSID wird exakt und getrennt von anderen Feldern gelesen. Profiländerungen
verwenden die UUID, niemals den angezeigten Verbindungsnamen. Mehrere kompatible
Profile mit derselben SSID werden abgewiesen, auch wenn eines gerade aktiv ist.
AP-/Ad-hoc-Profile, an andere Interfaces gebundene Profile, Controller-/Bridge-Port-
Profile und solche mit erweiterten `match.*`-Vorgaben sind ausgeschlossen.
Passende MAC-gebundene Profile werden abgewiesen, weil der installierte
NetworkManager die permanente MAC nicht über das geprüfte Feld bereitstellt;
der aktuellen, möglicherweise zufälligen MAC wird nicht vertraut. Ein von ctrl0
oder einem Interface derselben Funkhardware genutztes Profil ist geschützt.

Diese Operationen verbinden/trennen nicht, scannen nicht, wechseln keinen Modus
und ändern nicht das Geräte-`autoconnect`. NetworkManager kann ein freigegebenes
Profil selbst aktivieren, wenn seine normalen Bedingungen erfüllt sind.
`--autoconnect-off` trennt keine aktive Verbindung. `--autoconnect-on` hebt die
von `auto wifi --off` hinterlassene Gerätesperre nicht auf; Profilfreigabe und
Gerätefreigabe zur Laufzeit sind getrennt. Manuelles Verbinden funktioniert wie
zuvor und erhält dieses Laufzeitflag.

Das ausgewählte Profil wird vor dem Schreiben erneut und danach abschließend
geprüft. Bei Fehlern oder Unterbrechung wird nur das alte Autoconnect-Bit dieses
Profils wiederhergestellt, sofern Identitäts-/Bindungsmetadaten unverändert sind.
Ein gelöschtes oder unabhängig verändertes Profil wird nicht neu erzeugt oder
überschrieben; unvollständige Wiederherstellung wird gemeldet. Die Befehlssperre
serialisiert dieses Werkzeug, nicht unabhängige NetworkManager-Clients.

## Ausschalten und Betriebsarten

`--off` im Clientmodus trennt nur das ausgewählte Gerät und deaktiviert dessen
Autoconnect zur Laufzeit. Gespeicherte Profile und Schlüssel bleiben erhalten.
Wiederholung ist unbedenklich. Dies ist keine dauerhafte Funksperre: Neustart,
Hotplug oder ein ausdrücklicher Verbindungsauftrag können den Laufzeitzustand ändern.

`--monitor` prüft Treiberunterstützung, trennt den ausgewählten Client, gibt dieses
Gerät aus NetworkManager frei und schaltet das bestehende Interface mit `iw` in
den Monitor-Modus. Es erzeugt/löscht keine Interfaces und ändert weder
Regulierungsdomäne, Kanalkonfiguration noch andere Adapter. Unterstützt sind nur
normale Client-/Monitor-Übergänge.

`--managed` führt einen Monitor-Adapter in den Clientmodus und unter die
NetworkManager-Verwaltung zurück, anfangs getrennt mit deaktiviertem
Laufzeit-Autoconnect. **Ist er bereits im Managed-Modus unter NetworkManager,
bleibt eine bestehende Verbindung unverändert.** Ein ausdrückliches `--managed`
kann auch ein bisher unverwaltetes Clientinterface übernehmen; andere Modi wie
AP werden abgewiesen.

Im Monitor-Modus setzt `--off` nur den ausgewählten Link auf down; der Modus bleibt
erhalten. Ein späteres `--monitor` setzt ihn wieder auf up. Moduswechsel sind
Laufzeitänderungen, kein Bootdienst und keine dauerhafte Treiberkonfiguration.

Operationen werden serialisiert. Fehlgeschlagene Verbindungen oder Moduswechsel,
auch bei Unterbrechung, versuchen ursprünglichen Gerätemodus, administrativen
Linkzustand, NetworkManager-Zuständigkeit/Autoconnect und vorherige aktive
Profil-UUID wiederherzustellen. Die alte Verbindung wird mit ihren gespeicherten
Zugangsdaten ohne neue Passwortabfrage reaktiviert. Gespeicherte Profile werden
nie gelöscht. Verschwundener Adapter, veränderte Hardwareidentität, nicht mehr
verfügbares altes WLAN oder fehlgeschlagener nativer Befehl können vollständige
Wiederherstellung verhindern; dies wird ausdrücklich gemeldet. Das Skript kann
parallele unabhängige Änderungen anderer Administratoren oder Dienste nicht rückgängig machen.

## Status und Exitcodes

Status liest physisches Interface, Modus, administrativen und operativen
Kernel-Linkzustand getrennt, dazu NetworkManager-Zuständigkeit/-Zustand/-Autoconnect,
SSID und UUID des aktiven Profils sowie IPv4-/IPv6-Adressen. Er verbindet nicht,
scannt nicht und wechselt keinen Modus. `admin up` bedeutet aktiviertes Interface,
nicht verbundenes WLAN. `operational unknown` bleibt erhalten, wenn der Treiber
keinen Linkzustand meldet, etwa bei manchen Monitor-Interfaces; es wird weder up
noch down daraus abgeleitet. Hilfe und Status sind unprivilegiert; Änderungen benötigen Root.

Exit 0 bedeutet Erfolg, 1 einen Konfigurations-/nativen Operationsfehler und 2
ungültige CLI-Argumente. Eine Unterbrechung außerhalb einer Transaktion liefert
130. Eine unterbrochene Transaktion, die ihr Wiederherstellungsergebnis meldet, liefert 1.

## Prüfung

```sh
python3 kali/tools/components.py check --component wifi-control
```

Die eigenständige Fixture-Suite prüft USB-/Gesamt-PHY-Ausschluss, fehlende und
mehrere Adapter, geänderte Hardwareidentitäten, native Profilwiederverwendung ohne
geheime Argumente, Wechsel und Wiederherstellung, verdeckte Agent-Abfrage,
Client-/Monitor-Übergänge, nicht unterstützte Treiber, idempotentes OFF, Sperren,
Berechtigungen, Status und CLI-Validierung. Version 0.1.2 ergänzt reine
Profilpersistenz, exakte SSID-/UUID-Zuordnung, Ablehnung mehrdeutiger und geschützter/
fremder Profile, unveränderte Gerätebefehle, Idempotenz, Wiederherstellung nach
Teil-Schreibvorgang/Rücklesefehler/Unterbrechung, gelöschte oder parallel veränderte
Profile, Schutz dauerhafter Speicherung, Optionsvalidierung und direkt ausführbare
Hilfe. Zu diesem Stand waren die neuen Profilschalter durch Fixtures geprüft;
die Live-Abnahme war noch offen.

Native lesende Feldformate wurden gegen NetworkManager 1.56.1 und das installierte
`iw`/`ip` des v05-Pi geprüft. Echte Verbindungen/Passwortwiederverwendung, Wechsel
externer WLANs, Trennung, Monitor-/Managed-Wechsel und physische Wiederherstellung
blieben damals für den gemeinsamen Hardwaretest offen. Fixture-Erfolg ist keine
Hardwareabnahme. Die Vorbereitung dieser Komponente umfasst weder Image-Neubau
noch Live-Modus-/Verbindungsänderungen.

Primärquellen:
[NetworkManager-Profil-Autoconnect](https://networkmanager.dev/docs/api/latest/settings-connection.html),
[NetworkManager-nmcli-Handbuch](https://networkmanager.dev/docs/api/latest/nmcli.html),
[Native WLAN-Verbindungsimplementierung von NetworkManager 1.56.1](https://github.com/NetworkManager/NetworkManager/blob/1.56.1/src/nmcli/devices.c),
[Linux-Wireless-iw-Dokumentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html).

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# External USB Wi-Fi control

`auto wifi` command for the Pi4 control-network layout. Install together with
`auto-cli`. Version 0.1.5 supplies an event-driven saved-profile policy service;
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
that every outgoing connection uses the USB adapter; exclusive routing is
provided separately by `auto share`.

## Persistent autoconnect for a saved WLAN

Two targeted Pi reboots on 23 October 2026 verified the defaults and explicit
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
python3 kali/tools/components.py check --component wifi-control
```

The standalone fixture suite covers USB and whole-PHY exclusion, absent and
multiple adapters, changed hardware identities, native profile reuse without
secret arguments, switching and rollback, hidden-agent invocation, client/
monitor transitions, unsupported drivers, idempotent off, lock behavior,
permissions, status and CLI validation. Version 0.1.2 adds profile-only persistence,
exact SSID/UUID matching, ambiguity and protected/foreign-profile rejection,
unchanged device commands, idempotence, partial-write/readback/interruption rollback,
deleted/concurrently changed profiles, persistent-storage guards, option validation and direct executable help.
At that stage, the new profile switches were fixture-tested; live acceptance was still pending.

Native read-only field formats were checked against the v05 Pi's
NetworkManager 1.56.1 and installed `iw`/`ip`. Actual connection/password reuse,
external WLAN switching, disconnect, monitor/managed switching and physical
rollback were left for the joint hardware test at that stage. Fixture success is not a hardware
acceptance result. No image rebuild or live mode/connection change is part of
preparing this component.

Primary references:
[NetworkManager profile autoconnect](https://networkmanager.dev/docs/api/latest/settings-connection.html),
[NetworkManager nmcli manual](https://networkmanager.dev/docs/api/latest/nmcli.html),
[NetworkManager 1.56.1 native Wi-Fi connection implementation](https://github.com/NetworkManager/NetworkManager/blob/1.56.1/src/nmcli/devices.c),
[Linux Wireless iw documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html).

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
