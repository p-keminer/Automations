<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Zertifikatdownload steuern

Optionaler Befehl `auto cert` für das abgenommene nginx-Layout des Pi4.
Benötigt zusätzlich die optionale Dispatcher-Komponente `auto-cli`.
Beide Komponenten auswählen.

```sh
auto cert                  # same as --status
auto cert --status
sudo auto cert --off
sudo auto cert --on
auto cert --help
```

Alle Befehlsausgaben und Hilfen sind Englisch. Die Bash-Vervollständigungsdaten
enthalten die vier unterstützten Optionen. Hilfe und Status benötigen keine
Rootrechte; der Status benötigt allerdings Leserechte für die nginx-Konfiguration
und Zugriff auf systemd-Abfragen.

Geändert werden ausschließlich diese öffentlichen CA-Downloadpfade:

- HTTP `/cert`
- HTTP `/pi4-ca.crt`
- HTTPS `/cert`

`--off` ersetzt deren Downloadanweisungen durch `return 404;`.
`--on` stellt die bekannten Downloadanweisungen für die öffentliche
`/etc/pi4/tls/ca.crt` wieder her. Zertifikatdateien, TLS-Schlüssel, Firewallregeln,
Remotesitzungen, Guacamole-Proxy-Locations, andere nginx-Routen und die Aktivierung
des Dienstes bleiben unverändert. nginx wird weder gestoppt noch gestartet.
Bereits auf Clients installierte Zertifikate werden durch abgeschaltete Downloads
nicht ungültig.

Der feste Konfigurationspfad ist `/etc/nginx/conf.d/pi4-remote.conf`. Akzeptiert
werden nur die beiden bekannten v05-Listener und die drei bekannten Downloadblöcke.
Doppelte, fehlende oder angepasste Downloadblöcke werden abgewiesen. Eine gemischte
Ein-/Aus-Konfiguration darf auf den gewünschten Zustand vereinheitlicht werden.
Es gibt weder eine CLI-Pfadüberschreibung noch beliebige nginx-Befehlsausführung.

Änderungen nutzen eine exklusive Sperre und atomares Ersetzen der Datei, erhalten
Eigentümer, Gruppe und Modus und prüfen die nginx-Syntax vor dem Reload. Sowohl
Original als auch Kandidat müssen gültig sein. Bei ungültigem Kandidaten werden
die ursprünglichen Bytes wiederhergestellt. Ein fehlgeschlagener Reload löst
ebenfalls die Wiederherstellung mit Reload der ursprünglichen Konfiguration aus.
Eine gescheiterte Wiederherstellung wird ausdrücklich gemeldet. Beim Ersetzen
erkannte parallele Änderungen werden nicht überschrieben. Ein bereits eingestellter
Zustand führt weder zu einem Schreibvorgang noch zu einem unnötigen Reload.

Bei inaktivem oder fehlgeschlagenem nginx wird eine gültige Änderung für den
nächsten Start gespeichert; der Dienst startet nicht automatisch. Übergangszustände
werden abgewiesen. `--status` meldet den konfigurierten Zustand on/off/mixed und den
tatsächlichen systemd-Dienstzustand getrennt. Er behauptet nicht, dass die Datei
den aktuell von nginx geladenen Routen entspricht; HTTP-/HTTPS-Routen werden nicht
abgefragt. Eine unabhängige manuelle Änderung oder ein Reload außerhalb dieses
Befehls kann deshalb eine Prüfung durch den Betreiber erfordern. Die Transaktion
sichert parallele `auto cert`-Aufrufe ab, nicht jeden externen Administrator/Editor.

Exitstatus: 0 = Erfolg/Status, 1 = Operations-/Konfigurationsfehler,
2 = ungültige Befehlsargumente.

## Lokale Prüfungen

```sh
python3 kali/tools/components.py check --component cert-control
```

Die Tests verwenden temporäre Konfigurationen und simulierte Dienstbefehle. Sie
prüfen die Routenauswahl, den Erhalt anderer Inhalte und Berechtigungen, fehlerhafte
Eingaben, Idempotenz, inaktive Dienste, Wiederherstellung, parallele Änderungen,
Sperren und CLI-Berechtigungen. Sie starten nginx nicht neu, verändern den Pi nicht
und ersetzen keinen Hardwaretest mit der tatsächlich installierten nginx-Version.

Die Komponente ist optional und standardmäßig nicht ausgewählt. Ihre Installation
allein ändert die Downloadverfügbarkeit nicht. Zur Vorbereitung dieser Komponente
gehören weder ein Image-Neubau noch eine Archivveröffentlichung oder Live-Änderungen
am Pi.

## Pi4-Hardwareprüfung – 19.10.2026

Auf dem laufenden v05-Pi lieferten HTTP `/cert`, HTTP `/pi4-ca.crt` und HTTPS `/cert`
jeweils 200 → 404 → 200 für an → aus → an. Die Prüfungen erlaubten eine begrenzte
Wartezeit für den gleitenden nginx-Worker-Reload. Die SHA-256 des CA-Downloads war
vorher und nachher identisch; auch der ursprüngliche Hash der nginx-Konfiguration
wurde exakt wiederhergestellt.

HTTPS `/remote/` blieb bei ausgeschalteten Zertifikatdownloads mit Status 200
erreichbar. Die Haupt-PIDs aller sechs überwachten Dienste blieben unverändert;
wiederholtes `--off` bewirkte keine zusätzliche Änderung. Der lokale Nachweis heißt
`basic-controls-cert-hardware.json`. Dieser Test umfasste weder einen Pi-Neustart
noch eine neue Browserinteraktion.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Certificate download control

Optional `auto cert` command for the accepted Pi4 nginx layout.
Requires the optional `auto-cli` dispatcher component alongside this component.
Select both components.

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
python3 kali/tools/components.py check --component cert-control
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

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
