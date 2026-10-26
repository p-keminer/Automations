<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Sichtbarkeit des Steuer-WLANs

Optionale Komponente für das abgenommene Netzwerklayout des Kali-Pi4-Builders.
Zusammen mit `auto-cli` installieren; dieser Einstieg ruft `auto ap` auf und lädt
die Vervollständigung. Auswahl oder Installation ändern weder die AP-Konfiguration
noch starten sie einen Dienst neu.

```text
sudo auto ap --status
sudo auto ap --invisible
sudo auto ap --visible
auto ap --help
```

Ohne Argument gilt `--status`. Die lesende Statusabfrage unterscheidet die
konfigurierte Sichtbarkeit vom tatsächlichen AP-/Interfacezustand. Sie überprüft
ausgesendete Beacons ausdrücklich nicht unabhängig. Die Hilfe benötigt weder Root
noch Systemdateien; die Konfiguration des Standardimages ist nur für Root lesbar.
Für Status und Änderungen deshalb `sudo` verwenden.

## Änderung anwenden

`--visible` und `--invisible` planen einen kurzen, unabhängigen systemd-Worker unter
Root ein. Er speichert ausschließlich `ignore_broadcast_ssid` in
`/etc/hostapd/hostapd.conf` und startet **nur hostapd** neu, damit die Einstellung
sofort wirksam wird. Steuer-WLAN und Browser-/SSH-Verbindung werden kurz getrennt.
Danach mit demselben Netz verbinden und `sudo auto ap --status` aufrufen.
Guacamole-Dienste, Sitzungsprozesse, Passwörter, Client-ACLs und Netzwerkzuständigkeiten
bleiben unverändert. Eine unterbrechungsfreie Verbindung oder feste Wiederanmeldezeit
wird nicht zugesichert.

Die Einstellung übersteht einen Neustart. Eine verborgene SSID unterdrückt die
übliche Namensankündigung, bietet aber keinen zusätzlichen Zugriffsschutz. Neue
Clients benötigen möglicherweise den manuell eingegebenen exakten Netzwerknamen.
Auch beim bereits konfigurierten Wert wird hostapd bewusst neu gestartet: Ein
gespeicherter Wert beweist nicht, dass die Firmware ihn angewendet hat.

Der aufrufende Befehl meldet **scheduled**, nicht den Abschluss. Ein erfolgreicher
Planungs-Exitcode beweist keine erfolgreiche Anwendung. `--status` zeigt das letzte
Worker-Ergebnis: `queued`, `running`, `applied`, `recovered` oder `failed`.
`applied` bedeutet, dass ein geprüfter neuer hostapd-Prozess auf ctrl0 mit erwarteter
Adresse und Konfiguration ENABLED ist; es ist keine passive Funkmessung.
`recovered` zeigt, ob die vorherige Konfiguration wiederhergestellt wurde oder der
Worker nichts geändert hat. Eine fehlgeschlagene Wiederherstellung muss ein
Administrator prüfen.

## Gültigkeitsbereich und Wiederherstellung

Unterstützt werden nur die bekannte Single-BSS-Konfiguration des Kali-Builders,
die ctrl0-Namensregel und der Ausschluss aus NetworkManager. Geprüft werden der
aktuelle Daemon-Aufruf und die geladene Definition für den nächsten Start: exakter
Dienst samt Drop-in, Umgebungsdatei, effektiver Befehl und Umgebung, kein ausstehender
Daemon-Reload und keine unbekannten Exec-Hooks. Unbekannte, unsichere oder extern
veränderte Konfigurationen werden abgewiesen.

Der Worker ist der feste transiente Dienst `automations-ap-apply.service` und nutzt
das vertrauenswürdige installierte AP-Programm über isoliertes Python. Ein privater,
Root gehörender Datensatz unter `/run/automations-ap` und die bestehende AP-Sperre
koordinieren Aufrufe. Beliebige Jobbefehle, Pfade, Umgebungen oder ein überschriebenes
Test-Stammverzeichnis im Produktivbetrieb werden nicht akzeptiert. Parallele
Operationen werden abgewiesen; ein Verbindungsabbruch des Aufrufers beendet den
Worker nicht. Befehle und Bereitschaftsabfragen haben begrenzte Laufzeiten.

Schreibvorgänge verwenden eine temporäre Datei im selben Verzeichnis, erhalten
Eigentümer und Modus und nutzen fsync sowie atomares Umbenennen. Inhalt und Metadaten
werden unmittelbar vor dem Ersetzen erneut geprüft. Abgebrochen werden darf nur ein
exakt zugeordneter eigener systemd-Neustartjob. Der Jobmodus `fail` weist kollidierende
Jobs ab, statt sie zu ersetzen. Bei Fehlern klärt der Worker den Jobzustand, ersetzt
nur seine eigene unverändert gebliebene Ersatzdatei durch das Original und versucht,
die vorherige unterstützte Konfiguration neu zu starten. Externe Änderungen werden
weder überschrieben noch bewusst neu gestartet. ExecStopPost behandelt unvollständige
Worker-Wiederherstellungen; abgeschlossene Datensätze lösen keinen weiteren Neustart
aus. Zugangsdaten- und ACL-Dateien werden nicht gelesen.

Stromausfall oder erzwungenes Beenden der Wiederherstellung sind nicht vollständig
transaktional abgesichert. Wird der Aufrufer zwischen Aufzeichnung und Einplanung
des Workers beendet, kann ein blockierter queued-Datensatz zurückbleiben, ohne
hostapd zu ändern. Solche offenen Operationen müssen geprüft werden. Während einer
aktiven Operation weder den privaten Datensatz löschen noch hostapd parallel
bearbeiten. Der normale Status darf Wiederherstellung oder Funkerfolg nur mit den
jeweils erforderlichen Nachweisen melden.

Exitcodes: `0` für Beobachtung oder erfolgreiche Einplanung, `1` für eine unsichere/
nicht verfügbare Plattform oder einen Operationsfehler, `64` für ungültige Argumente,
`77` für Änderungen ohne Root und `130` bei Unterbrechung des Aufrufers. Status kann
einen fehlenden/deaktivierten AP melden; Änderungsbefehle erzeugen oder starten ihn nicht.

## Prüfung

`python3 kali/tools/components.py check --component ap-control` ausführen. Die Tests
nutzen temporäre Fixtures und simulierte Befehlsausführung. Sie prüfen öffentliche
Optionen, native Definitionsabfragen von systemd 262, Schutz des nächsten Starts,
tatsächlichen gegenüber gespeichertem Zustand, Vertrauen in den festen Worker,
Jobkonflikte, doppelte Anfragen, Firmwareabweichungen trotz gleicher Konfiguration,
Bereitschaft mit neuer PID, CAS-Schreibvorgänge, Unterbrechung und Wiederherstellung,
externe Änderungen, Berechtigungen und das Unterdrücken von Geheimnissen.
Es werden keine Pi- oder Netzwerkbefehle ausgeführt.

Die frühere SET/UPDATE_BEACON-Implementierung meldete Erfolg und erhielt die
AP-Verbindung. Eine unabhängige Aufnahme der eigenen BSSID am 19.10.2026 zeigte nach
der Anforderung des verborgenen Modus jedoch weiterhin den Namen `Pi4`. Die festgelegte
brcmfmac-Implementierung aktualisiert `closednet` in der Firmware beim AP-Start;
change-beacon aktualisiert lediglich zusätzliche Management-IEs. Die früheren
Prüfungen belegten deshalb keine verborgenen Beacons. Version 0.1.2 ersetzt diesen
Weg durch den zeitlich begrenzten Neustart-Worker.

Der neue Worker bestand Offline-Prüfung und Fixtures. Sichtbar/verborgen/sichtbar
muss weiterhin anhand echter Beacons abgenommen werden, ebenso Wiederverbindung und
Fortbestand von Guacamole/Sitzungen. Hier wird kein neuer Hardwareerfolg behauptet.

Primärquellen:

- [Raspberry-Pi-brcmfmac: AP-Start und change-beacon](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.12.y/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c).
- [Lebenszyklus transienter systemd-Dienste](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
- [systemd-D-Bus-Eigenschaften für Jobs und Dienste](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

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

Run `python3 kali/tools/components.py check --component ap-control`. Tests use temporary
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

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
