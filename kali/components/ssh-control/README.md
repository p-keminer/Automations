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
python3 tools/components.py check --component ssh-control
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
Arbeitsnetz wurden dabei nicht durchgeführt; diese Prüfungen bleiben offen.

Die neue selektive Abmeldung in 0.1.3 benötigt einen eigenen Hardwaretest mit
paralleler direkter SSH-Verbindung und Guacamole-Sitzungen. Die obigen alten
Ergebnisse belegen diese geänderte Semantik nicht.

Bei abgezogenem Freigabe-Uplink bleibt die SSH-Steuerung bedienbar. Die fehlende
Schnittstelle muss zum ausschließlich von Root les- und schreibbaren
V2-Freigabezustand passen. Sämtliche tatsächlichen INPUT-Regeln werden weiterhin
exakt auf Reihenfolge und Gültigkeitsbereich geprüft; der IPv6-DNS-Präfix muss
zusätzlich zum gespeicherten Zustand passen. Fehlender, unsicherer oder
widersprüchlicher Zustand wird abgewiesen.
