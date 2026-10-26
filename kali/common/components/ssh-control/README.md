<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Direkten SSH-Zugang schalten

Optionale Komponente `ssh-control` für das abgenommene Pi4-v05-Image. Voraussetzung
für den Aufruf ist die separat ausgewählte Komponente `auto-cli`; dieses Paket
installiert ausschließlich ihr Unterkommando und statische Vervollständigungen.

Version 0.1.5 erkennt zusätzlich die Quellenauswahl von share-control 0.1.8:
vorangestellte DNS-Sperren abgewählter Netze und die engen DNS-Freigaben für
den zusätzlichen AP werden mit vollständigen Ausdrücken und fester Reihenfolge
geprüft. Widersprüchliche Auswahlregeln bleiben ein Fehler. Geschützter
V2-Share-Zustand darf die festgelegte Gastrolle und Quellenauswahl enthalten,
auch wenn der ausgewählte USB-Ausgang fehlt. Es werden keine Share-Regeln geändert.

Version 0.1.4 ergänzte die optionale Tor-/Proxy-Komposition: Ist deren Helper
installiert, wird der Share-Lock zusätzlich gehalten und ausschließlich dessen
vollständig geprüfte INPUT-Erweiterung vom vorhandenen SSH-Guard getrennt.
Die gesamte private Firewall wird dabei geprüft, einschließlich ihrer engen
Share-OUTPUT-Ergänzungen. Geänderte oder verwaiste Regeln werden abgewiesen.
Ohne Helper bleibt SSH eigenständig. `PRIVACY_API = 1` kennzeichnet diesen Vertrag.

```sh
auto ssh --help
sudo auto ssh
sudo auto ssh --status
sudo auto ssh --on
sudo auto ssh --off
```

Ohne Argument wird der Status angezeigt. Hilfe funktioniert ohne Rootrechte.
Status und Änderungen benötigen Rootrechte, um die privaten Konfigurationsdateien,
Prozesszuordnung der Listener und tatsächlichen Firewallregeln zu prüfen. Alle
CLI-Ausgaben und Fehlermeldungen sind englisch. Aktionen sind gegenseitig exklusiv.

`--on` erlaubt neue direkte SSH-Verbindungen auf TCP 22 ausschließlich über `ctrl0`.
`--off` entfernt diesen Listener und die zugehörige Freigabe und beendet danach
**auch bestehende direkte SSH-Verbindungen auf dem lokalen TCP-Port 22**.
Die getrennte Guacamole-Shell auf `127.0.0.1:2222`, Desktop und tmux-Sitzungen
werden nicht gestoppt. Das gemeinsame SSH-Hauptprogramm erhält für die
Listeneränderung nur ein HUP-Signal; kein SSH-Dienst wird neu gestartet.

Der gesamte OFF-Ablauf läuft in einem festen kurzlebigen root-systemd-Dienst
`automations-ssh-off.service`. Deshalb läuft er auch weiter, wenn die aufrufende
direkte SSH-Verbindung sich selbst trennt. Guacamole-Aufrufer warten auf das
Ergebnis. Gleichzeitige Änderungen werden über dieselbe Sperre wie `--on`
abgewiesen. Das Journal des Workers ist mit
`sudo journalctl -u automations-ssh-off.service` verfügbar. Es enthält keine
Passwörter oder Konfigurationsinhalte.

Die selektive Abmeldung verwendet die Socket-Inodes des **lokalen** Ports 22,
root-eigene `sshd-session`-Monitore unmittelbar unter dem geprüften Hauptprozess
und Linux-pidfds. Executable, Prozessstart, Eigentümer, Elternprozess und
Socketzuordnung werden unmittelbar vor SIGTERM erneut geprüft. Ein Monitor mit
einem Port-2222-Socket wird nie ausgewählt; ausgehende SSH-Verbindungen bleiben
ebenfalls unberührt. Es gibt keinen Prozessnamen-/Prozessbaum-Kill und keinen
Conntrack-Flush. OpenSSH reicht das Signal an das zugehörige Sitzungskind weiter.
Erfolg erfordert anschließend, dass keine direkten Transport-Sockets mehr
vorhanden sind. Wiederholtes `--off` prüft und bereinigt auch Restverbindungen,
wenn Listener und Freigabe bereits abgeschaltet sind.

Die Einstellung bleibt nach einem Neustart erhalten. Geändert werden ausschließlich
die bekannten v05-Dateien `/etc/pi4/sshd_config`, `/etc/nftables.conf` und bei Bedarf
die nftables-Startabhängigkeit in `/etc/systemd/system/pi4-shell.service`. Letztere
bleibt auch nach dem Ausschalten erhalten. Sie verhindert bei ursprünglich ohne
direktes SSH gebauten Images, dass TCP 22 beim nächsten Boot vor der Firewall
geöffnet wird. Der vorhandene IPv4-Listener `0.0.0.0:22` wird wie in v05 durch die
Firewall auf das Steuerinterface begrenzt; kein IPv6-Listener wird hinzugefügt.

Vor Änderungen werden Eigentümer, Berechtigungen, bekannte Konfigurationsformen,
geladene Diensteinheit, Listener und sämtliche Regeln der Pi4-Eingangskette geprüft.
Abweichende Anpassungen, weitere Freigaben, abweichende Listener oder Drop-ins
führen zu einer Fehlermeldung. Es erfolgt keine automatische Reparatur fremder
Konfigurationen. Änderungen werden durch eine rootgeschützte exklusive Sperre
serialisiert; Kandidaten durch `sshd -t` und `nft --check` geprüft. Live wird nur
die einzelne SSH-Freigabe per Regelhandle entfernt oder hinzugefügt. **Kein Flush
des laufenden Regelwerks**, kein Neustart von nftables oder SSH.

Bei einem Fehler während der reversiblen Konfigurationsänderung werden die
vorherigen Dateien und die einzelne SSH-Freigabe wiederhergestellt; die Listener
werden erneut geprüft. Falls auch die
Wiederherstellung scheitert, meldet das Programm ausdrücklich `Rollback incomplete`
und endet ungleich null. Das gilt auch für einen Abbruch mit Strg+C während der
Änderung. Dateieigentümer, Gruppe und Modus bleiben erhalten. Erkannte gleichzeitige
Änderungen anderer Administratoren werden beim Schreiben oder Zurückrollen nicht
überschrieben, sondern als Konflikt gemeldet. Ein Stromausfall zwischen mehreren Dateischreibvorgängen
ist keine vollständig atomare Transaktion; danach melden Konsistenzprüfungen eine
Abweichung, statt einen erfolgreichen Zustand vorzutäuschen.

Nach erfolgreicher OFF-Konfiguration beginnt die getrennte Abmeldung. Fehler in
diesem Schritt öffnen SSH **nicht wieder**. Das Programm meldet ungleich null:
`New direct SSH connections remain blocked; existing direct SSH connections could
not all be terminated.` Weil die bestehende Firewall etablierte Verbindungen
zulässt, können nicht beendete Verbindungen dann noch nutzbar sein. Der Fehler
ist daher keine Bestätigung einer vollständigen Sperre. `--status` zeigt die
Anzahl noch vorhandener direkter Transport-Sockets; danach kann `--off` erneut
ausgeführt werden. Kernel-only TIME_WAIT-Einträge zählen nicht als Verbindung.

Der Status zeigt den geprüften Zustand, direkte Transport-Sockets und die vorhandenen Interfaces
mit Adressen. Diese erste Fassung ist absichtlich an die geprüfte v05-Struktur
gebunden. Die ausdrücklich abgestimmten `auto share`-Zusatzregeln werden nur in
ihrer vollständigen Reihenfolge und engen Form akzeptiert: IPv4-DNS sowie die
IPv6-Aufnahmephase beziehungsweise die aktive Freigabe mit dem vorhandenen
externen Interface, festgelegten ICMPv6-/DHCPv6-Typen und optionalem DNS auf
Port 1053 im ULA-/64-Steuernetz. Unbekannte oder weiter gefasste Regeln bleiben
ein Fehler; ein Kommentar allein legitimiert keine Freigabe.

## Lokale Prüfung

```sh
python3 kali/tools/components.py check --component ssh-control
```

Fixtures prüfen Ein-/Ausschalten, Zustandserhalt, Idempotenz, unbekannte Regeln,
unsichere Dateien, fehlendes Steuernetz, Kandidatenfehler und Wiederherstellung.
Zusätzlich prüfen sie die selektive Port-22-Abmeldung bei parallelem Guacamole-
Socket, ausgehende SSH-Verbindungen, falsche Prozessidentitäten, PID-Wechsel,
Signalfehler, Restverbindungen, den festen Worker und dessen durchgängige Sperre.
Die native JSON-Darstellung von nftables 1.1.7 ist zusätzlich als bereinigte
Regressionstest-Fixture enthalten. Diese Tests ändern keine Hostfirewall.

## Neustartprüfung am 23.10.2026 (Version 0.1.5)

Beide tatsächlichen Builder-Konfigurationen (direktes SSH an/aus) wurden auf
demselben Pi gebootet, ohne ein weiteres Image zu bauen oder zu flashen. Bei
SSH aus funktionieren neue Guacamole-Shells; direkte Verbindungen scheitern.
`--on` ermöglicht anschließend eine echte Anmeldung und ergänzt die notwendige
Firewall-Startabhängigkeit. Bei SSH an funktioniert die direkte Anmeldung nach
dem Boot; `--off` beendet eine zuvor authentifizierte direkte Testverbindung
und blockiert neue Verbindungen, während dieselbe Guacamole-Shell erhalten
bleibt. SSH-Hauptprozess und Guac-Webdienste behalten bei den Umschaltungen
ihre Instanzen. Ein separater LAN-Zugriffsversuch auf Port22 bleibt gesperrt.
Abschließend ursprüngliche SSH-Dateien/Basisfirewall und eingeschalteter
ctrl0-Zugang wiederhergestellt. Details und separate Boot-/Shutdownbefunde im
Builder-Bericht `build/evidence/ssh-wifi-postimplementation-review-20261023.json`.
Diese warmen Neustarts sind kein neuer physischer Kaltstart oder Dauerlauf.

## Historische Hardwareprüfung am 19.10.2026 (bis Version 0.1.1)

Auf dem Pi bestanden: `--off` blockiert neue Verbindungen auf TCP 22, während die
bestehende SSH-Verbindung erhalten bleibt. Der SSH-Banner auf Loopback-Port 2222
und HTTPS `/remote/` mit HTTP 200 bleiben erreichbar; die sechs geprüften
Dienst-PIDs ändern sich nicht. Wiederholtes Ausschalten ist idempotent. Nach
`--on` funktioniert eine neue SSH-Anmeldung wieder, die ursprünglichen
Konfigurationsprüfsummen sind wiederhergestellt und die geprüften Dienste gesund.
Der vorbereitete einmalige Wiederherstellungstimer wurde anschließend erfolgreich
aufgehoben. Die native Firewallstruktur wurde geprüft.

Ein Neustarttest und ein tatsächlicher Zugriffsversuch aus einem externen
Arbeitsnetz wurden dabei nicht durchgeführt; diese Prüfungen waren zu diesem Stand noch offen.

Die neue selektive Abmeldung in 0.1.3 benötigt einen eigenen Hardwaretest mit
paralleler direkter SSH-Verbindung und Guacamole-Sitzungen. Die obigen alten
Ergebnisse belegen diese geänderte Semantik nicht.

Bei abgezogenem Freigabe-Uplink bleibt die SSH-Steuerung bedienbar. Die fehlende
Schnittstelle muss zum ausschließlich von Root les- und schreibbaren
V2-Freigabezustand passen. Sämtliche tatsächlichen INPUT-Regeln werden weiterhin
exakt auf Reihenfolge und Gültigkeitsbereich geprüft; der IPv6-DNS-Präfix muss
zusätzlich zum gespeicherten Zustand passen. Fehlender, unsicherer oder
widersprüchlicher Zustand wird abgewiesen.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Switching direct SSH access

Optional `ssh-control` component for the accepted Pi4 v05 image. Invocation
requires the separately selected `auto-cli` component; this package installs
only its subcommand and static completions.

Version 0.1.5 additionally recognizes share-control 0.1.8's source selection:
leading DNS blocks for excluded networks and narrow DNS admissions for the
additional AP are checked using complete expressions and a fixed order.
Conflicting selection rules remain an error. Protected V2 Share state may
contain the fixed guest role and source selection even when the selected USB
output is missing. No Share rules are changed.

Version 0.1.4 added optional Tor/proxy composition: if its helper is installed,
the Share lock is also held and only its fully validated INPUT extension is
separated from the existing SSH guard. The entire private firewall is checked,
including its narrow Share OUTPUT additions. Modified or orphaned rules are
rejected. Without the helper, SSH remains independent. `PRIVACY_API = 1`
identifies this contract.

```sh
auto ssh --help
sudo auto ssh
sudo auto ssh --status
sudo auto ssh --on
sudo auto ssh --off
```

Without an argument, status is shown. Help works without root. Status and changes
require root to inspect private configuration files, listener process ownership
and actual firewall rules. All CLI output and errors are English. Actions are
mutually exclusive.

`--on` allows new direct SSH connections on TCP 22 exclusively through `ctrl0`.
`--off` removes that listener and its admission, then terminates **existing direct
SSH connections on local TCP port 22 as well**. The separate Guacamole shell on
`127.0.0.1:2222`, desktop and tmux sessions are not stopped. The shared SSH master
process receives only HUP for the listener change; no SSH service is restarted.

The entire OFF operation runs in the fixed, short-lived root systemd service
`automations-ssh-off.service`. It therefore continues if the invoking direct SSH
connection disconnects itself. Guacamole callers wait for the result. Concurrent
changes are rejected using the same lock as `--on`. The worker journal is
available with `sudo journalctl -u automations-ssh-off.service`. It contains no
passwords or configuration contents.

Selective disconnection uses socket inodes for **local** port 22, root-owned
`sshd-session` monitors directly below the validated master process, and Linux
pidfds. Executable, process start, owner, parent process and socket mapping are
rechecked immediately before SIGTERM. A monitor with a port-2222 socket is never
selected; outgoing SSH connections also remain untouched. There is no process-
name/process-tree kill or conntrack flush. OpenSSH forwards the signal to the
associated session child. Success requires no remaining direct transport
sockets. Repeated `--off` checks and cleans up residual connections even when
the listener and admission are already disabled.

The setting persists across reboot. Only the known v05 files `/etc/pi4/sshd_config`,
`/etc/nftables.conf` and, if needed, the nftables startup dependency in
`/etc/systemd/system/pi4-shell.service` are changed. The latter remains after
switching off. For images originally built without direct SSH, it prevents TCP 22
from opening before the firewall at the next boot. As in v05, the existing IPv4
listener `0.0.0.0:22` is restricted to the control interface by the firewall;
no IPv6 listener is added.

Before changes, the command validates ownership, permissions, known configuration
forms, the loaded service unit, listeners and every rule of the Pi4 input chain.
Custom modifications, additional admissions, different listeners or drop-ins
produce an error. Foreign configurations are not repaired automatically.
A root-protected exclusive lock serializes changes; candidates are checked with
`sshd -t` and `nft --check`. Only the individual SSH admission is removed by rule
handle or added live. **No flush of the active ruleset**, no nftables or SSH restart.

If the reversible configuration change fails, the previous files and individual
SSH admission are restored and listeners rechecked. If restoration also fails,
the command explicitly reports `Rollback incomplete` and exits nonzero. This
also applies to Ctrl+C during the change. File owner, group and mode are retained.
Detected concurrent edits by other administrators are not overwritten during
writing or rollback; they are reported as conflicts. Power loss between multiple
file writes is not a fully atomic transaction; subsequent consistency checks
report a mismatch instead of pretending success.

Separate disconnection starts after successful OFF configuration. Errors in
this step **do not reopen** SSH. The command exits nonzero and reports:
`New direct SSH connections remain blocked; existing direct SSH connections could
not all be terminated.` Because the existing firewall admits established
connections, connections that were not terminated may still be usable. This
error therefore does not confirm complete blocking. `--status` shows the number
of remaining direct transport sockets; `--off` may then be repeated. Kernel-only
TIME_WAIT entries do not count as connections.

Status shows the validated state, direct transport sockets and available
interfaces with addresses. This first implementation is intentionally tied to
the validated v05 structure. Explicitly agreed `auto share` additions are accepted
only in their complete order and narrow form: IPv4 DNS and either the IPv6
admission phase or active admission with the existing external interface, fixed
ICMPv6/DHCPv6 types and optional DNS on port 1053 in the ULA /64 control network.
Unknown or broader rules remain errors; a comment alone does not legitimize admission.

## Local checks

```sh
python3 kali/tools/components.py check --component ssh-control
```

Fixtures cover on/off switching, state preservation, idempotence, unknown rules,
unsafe files, missing control network, candidate failures and restoration. They
also check selective port-22 disconnection alongside a Guacamole socket,
outgoing SSH connections, wrong process identities, PID changes, signal failures,
residual connections, the fixed worker and its continuous lock. The native JSON
representation of nftables 1.1.7 is included as a sanitized regression fixture.
These tests do not change the host firewall.

## Reboot verification on 2026-10-23 (version 0.1.5)

Both actual builder configurations (direct SSH on/off) were booted on the same
Pi without building or flashing another image. With SSH off, new Guacamole
shells work while direct connections fail. `--on` then allows a real login and
adds the necessary firewall startup dependency. With SSH on, direct login works
after boot; `--off` terminates a previously authenticated direct test connection
and blocks new connections while the same Guacamole shell survives. SSH master
and Guacamole web services retain their instances during switching. A separate
LAN connection attempt to port 22 remains blocked. Finally, the original SSH
files/base firewall and enabled ctrl0 access were restored. Details and separate
boot/shutdown findings are in the builder report
`build/evidence/ssh-wifi-postimplementation-review-20261023.json`. These warm
reboots are not a new physical cold start or duration test.

## Historical hardware verification on 2026-10-19 (through version 0.1.1)

Passed on the Pi: `--off` blocks new TCP-22 connections while retaining the
existing SSH connection. The SSH banner on loopback port 2222 and HTTPS `/remote/`
with HTTP 200 remain reachable; the six inspected service PIDs do not change.
Repeated OFF is idempotent. After `--on`, a new SSH login works again, original
configuration checksums are restored and the inspected services are healthy.
The prepared one-time recovery timer was then successfully cancelled. The native
firewall structure was checked.

No reboot test or actual access attempt from an external working network was
performed in that test; those checks remained open at that stage.

The selective disconnection added in 0.1.3 requires its own hardware test with
parallel direct SSH and Guacamole sessions. Those older results do not prove
the changed semantics.

SSH control remains usable with the sharing uplink unplugged. The missing
interface must match the V2 Share state readable and writable only by root.
All actual INPUT rules are still checked for exact order and scope; the IPv6
DNS prefix must also match stored state. Missing, unsafe or inconsistent state
is rejected.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
