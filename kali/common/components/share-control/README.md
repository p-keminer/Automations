<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Internetfreigabe über einen ausgewählten Uplink

Optionale Komponente `share-control` **0.2.0**, zusammen mit `auto-cli` installiert.
Die Installation aktiviert keine Freigabe. Vorausgesetzt wird das abgenommene
Pi4-v05-Netzwerklayout.

Verschwindet das eigene Gast-AP-veth, kann Linux die erhaltene Eingangs-Policyregel
als abgetrennt markieren. Die Bereinigung akzeptiert nur diese exakte reservierte
Regel ohne lebendes Gast-veth und entfernt sie ohne Auflösung des fehlenden
Gerätenamens. Die Live-Zustandsprüfung weist sie weiterhin ab; fremde, veränderte
und doppelte Regeln bleiben Fehler.

Die optionale Anonymitäts-Runtime kombiniert exakt eigene INPUT-/OUTPUT-Freigaben
mit dieser Richtlinie. Solange Tor konfiguriert ist, werden manuelle Uplink-/
Quellenwechsel abgewiesen; zuerst diesen Modus ausschalten. Automatische
Aktualisierungen desselben ausgewählten Uplinks nutzen die koordinierte
Aktualisierung ohne Tor-Neustart oder -Sperre. Ohne optionalen Helper bleiben die
normalen Freigabevorgaben unverändert. `PRIVACY_API = 1` verhindert die Verwendung
inkompatibler älterer Share-Pakete durch die neue Runtime.

```sh
sudo auto share --wifi [--to wlan0] [--from ctrl0,wlan1]
sudo auto share --lan [--to eth0] [--from ctrl0,wlan1]
sudo auto share --off
sudo auto share --status
auto share --help
```

`auto share` ohne Argument zeigt den Status. Bei mehreren geeigneten Uplinks listet
ein TTY Namen, Verbindungszustand und WLAN-SSIDs zur Auswahl. Ohne TTY `--to` angeben.
Es bezeichnet immer den Ausgang/Uplink, nicht das eingehende Netz. Das frühere
`--interface` bleibt als Kompatibilitätsalias erhalten; beide Selektoren zusammen
werden vor jeder Netzwerkoperation abgewiesen.
Ohne `--from` wird stets gefragt, welche Clientnetze Internet erhalten sollen:
`ctrl0` und bei laufendem Zusatz-AP dessen physischer Adaptername. Eine Nummer/
einen Namen oder durch Kommas getrennte Auswahl eingeben. Es gibt keinen impliziten
Standard; Strg+C bricht ab. Nichtinteraktive Aufrufe benötigen
`--from NAME[,NAME...]`. Ein ausdrücklich genannter AP-Name muss aktuell den
Zusatz-AP betreiben; normale Clientadapter sind Uplinks, keine Freigabequellen.
Der Pi folgt immer dem ausgewählten Uplink. Ausgeschlossene Clientnetze können
weder Weiterleitung, gemeinsames DNS noch Tor-Listener nutzen; lokale Steuerung
und Willkommensseite bleiben erreichbar. Tor übernimmt die gewählten Quellnetze.
WLAN muss ein externes USB-Funkgerät sein; ctrl0 und dessen interne Funkhardware
sind ausgeschlossen. Die ausgewählte NetworkManager-Verbindung muss bereits
nutzbare IPv4-Adressierung, Gateway und DNS haben. Reine IPv6-Uplinks werden
abgewiesen; NAT64/DNS64 sind nicht implementiert. Dieser Befehl baut keine
Uplinkverbindung auf und trennt sie auch nicht.

Bei aktiver Freigabe verwenden **dieser Pi und die ausgewählten Clientnetze**
ausschließlich den gewählten Uplink. IPv4, verfügbares natives IPv6 und UDP-/TCP-DNS
folgen dieser Auswahl. Es gibt keinen Ausweichweg über andere Adapter, auch nach
Entfernung des gewählten Adapters. Bestehende an andere Uplinks gebundene Sockets
können ausfallen. Lokale Steuerung und Loopback bleiben erreichbar. `--off` entfernt
die Freigabe und stellt das normale Pi-Routing wieder her.

## DNS und IPv6

NetworkManager-DNS-Arrays können getrennte Zeilen oder mehrere mit ` | ` verbundene
Adressen enthalten. IPv4 und IPv6 werden vor Verwendung geparst und validiert;
fehlerhafte Metadaten erzeugen einen begrenzten Fehler mit Kontext, ohne zu
behaupten, die Freigabe sei ausgeschaltet. Link-Local-Gültigkeitsbereiche müssen
zum ausgewählten Interface passen. Version 0.1.5 korrigiert dieses im Gast-WLAN
entdeckte native Arrayformat; ältere gebaute Archive bleiben unverändert.
Paketpfad und RA-/Dienstkonfiguration bleiben gegenüber 0.1.4 unverändert.

Ein separater dnsmasq-Prozess auf Port 1053 mit fester Identität nobody/nogroup
beantwortet lokale und Client-DNS-Anfragen und leitet ausschließlich an ausgewählte
DNS-Server weiter. Er lädt weder resolv.conf noch die Hauptkonfiguration von dnsmasq.
UDP- und TCP-DNS werden für Pi und Steuerclients umgeleitet; exakte Ausnahmen für
Resolver-UID/Interface/Server verhindern rekursives Abfangen. IPv6-Link-Local-DNS
erlaubt ebenfalls nur diese UID, das ausgewählte Interface, konfigurierte Ziel
und den DNS-Port. Der lokale pi4-Eintrag bleibt erhalten. Verschlüsseltes DNS wird
nicht abgefangen, folgt aber weiterhin dem ausgewählten Uplink und Ausgangsschutz.

Die Serverliste liegt in einer Root gehörenden Laufzeitdatei, die Clients nicht
beschreiben können. dnsmasq liest sie bei SIGHUP ohne Prozessneustart erneut ein.
Unter Tor verwendet das Frontend den lokalen Tor-DNS-Endpunkt direkt: Physisch
interfacegebundene DNS-Sockets können OUTPUT-DNAT-Loopback-Antworten nicht zuverlässig
empfangen. Der private Filter verbietet weiterhin direkten Resolverausgang.
Tor OFF lädt die ausgewählten, ausdrücklich gebundenen Uplinkserver erneut.
Bei Tor-Nutzung benötigt dies anonymity-runtime 0.1.6.

Eine temporäre, eng begrenzte INPUT-Freigabe erlaubt Upstream-RA/ND, erforderliche
ICMPv6-Fehler, MLD-Abfragen und DHCPv6-Antworten sowie RS/ND auf der Steuerseite.
Eine begrenzte Router-Solicitation lässt die bestehende NetworkManager-Verbindung
IPv6 erkennen. Erforderlich sind eine globale Unicast-Adresse und nutzbare
Standardroute. Prüfungs-/Einrichtungsfehler verhindern die Aktivierung; sie werden
nicht als fehlende IPv6-Fähigkeit ausgegeben.

Bei nutzbarem IPv6 werden eine stabil aus der Maschine abgeleitete ULA /64 und eine
Link-Local-Adresse an ctrl0 ergänzt. dnsmasq kündigt diese ULA über RA/SLAAC mit
RDNSS an; NAT66 übersetzt Clientverkehr auf den gewählten Uplink. Präfixdelegation
ist nicht nötig. Der RA-Daemon lässt ctrl0 ausdrücklich über den Interfacenamen zu;
dnsmasq nutzt listen-address-Einträge nicht für seine RA-Interfaceprüfung. Sein
ergänzter DNS-Link-Local-Socket wird nur mit exaktem ctrl0-Gültigkeitsbereich
akzeptiert. Upstream-Listener werden abgewiesen. Ohne nutzbares IPv6 nach
abgeschlossener Erkennung sperren eine abschließende unreachable-Route und die
Firewall den externen IPv6-Ausgang. Es gibt keinen Ausweichweg über andere Interfaces.

## Zuständigkeit und Wiederherstellung

* IPv4-/IPv6-Routingtabelle **17855** und Prioritäten **17853–17856** sind reserviert.
  Regeln wählen ctrl0 und lokal erzeugten Verkehr (`iif lo`). Exakte Link-Local-,
  Multicast- und DHCP-Broadcast-Regeln erhalten nötige Linkverwaltung. Jede Familie
  hat eine abschließende unerreichbare Standardroute; unbekannte Policyregeln werden
  abgewiesen. Hauptstandardrouten und NetworkManager-Profile werden nicht umgeschrieben.
* Firewallobjekte sind auf `inet auto_share`, eine eigene Pi4-Forwarding-Kette samt
  Sprung und exakte führende INPUT-Ausnahmen begrenzt. Das temporäre
  `inet auto_share_gate` sperrt externen Ausgang und Weiterleitung während
  Übergängen. Es dient ausdrücklichem Ein-/Ausschalten/Wechsel, niemals automatischer
  Aktualisierung im laufenden Betrieb. Alle Pi4-Basisregeln einschließlich aktueller
  SSH-Auswahl werden geprüft. Der endgültige INPUT-Vertrag umfasst zwei IPv4-DNS-
  Regeln, sechs IPv6-Aufnahmeregeln und bei Aktivierung zwei ULA-DNS-Regeln.
  `auto ssh` prüft diese exakten Formen.
* Conntrack-Markierung **0x4155544f** kennzeichnet ausgewählten/umgeleiteten Verkehr.
  Stoppen/Wechsel löscht nur diese Zuordnungen; fremde lokale/Steuerverbindungen
  werden nicht geleert. Automatische Aktualisierung löscht sie nie. Bestehende
  eigene Verbindungen bleiben auf dasselbe ausgewählte Interface begrenzt, auch
  wenn eine noch gültige alte Adresse nicht mehr bevorzugt wird. Die
  Tor-Transportausnahme behält UID-, TCP- und IPv4-Grenzen; sie erlaubt unter Tor
  weder direkten Anwendungsverkehr noch IPv6.
* IPv4-Forwarding je Interface und alle vorhandenen IPv6-Forwardingwerte werden
  gespeichert. Globales IPv6-Forwarding wirkt unter Linux auf Interfaces; fremde
  Interfacewerte werden deshalb sofort und beim Stoppen erneut wiederhergestellt.
  Bei entfernten Adaptern muss kein nicht vorhandenes sysctl wiederhergestellt
  werden; neue Adapter behalten bei der Bereinigung ihren beobachteten Wert.
* IPv6-Adressen werden erst nach erfolgreicher Erzeugung als eigene erfasst.
  Gleiche vorhandene Adressen werden abgewiesen, niemals übernommen oder entfernt.
  Die Erkennung doppelter Adressen muss abgeschlossen sein. Vor dem Entfernen
  sendet Stoppen eine RA mit Lebenszeit null; kann sie nicht gesendet werden,
  wird Weiterleitung trotzdem abgeschaltet und eine Warnung ausgegeben. Clients
  können eine unbrauchbare Adresse bis zum angekündigten Ablauf behalten.
* Nur für Root zugängliche Sperre/Zustand und die Diensteinheit liegen unter `/run`.
  Fehler und Strg+C versuchen Wiederherstellung; unvollständige Bereinigung erhält
  Guard/Zustand für `--off`. Unbekannte Änderungen werden abgewiesen. Fehlgeschlagene
  Wechsel versuchen die vorherige nutzbare Auswahl wiederherzustellen.
  Nicht abfangbarer Prozessabbruch oder Stromausfall kann unvollständigen
  Laufzeitzustand hinterlassen; der nächste Befehl meldet ihn statt Erfolg anzunehmen.

Freigabe ist standardmäßig aus und endet beim Neustart. Dauerhafte DHCP-/AP-/NM-
Konfiguration und Systemresolverdatei bleiben unverändert. Ein nur zur Laufzeit
bestehender Timer prüft lokale Metadaten alle 30 Sekunden. Zwei übereinstimmende
Beobachtungen bestätigen DNS-/Adress-/Gateway-/IPv6-Änderungen. Er wählt nie ein
anderes Interface oder eine andere Quelle, führt keine fortlaufenden Internetproben
aus und setzt kein Downloadzeitlimit. Ein fehlender Uplink wird gemeldet, ohne
funktionierenden Zustand abzubauen oder einen anderen Weg zu öffnen.

Eine Aktualisierungstransaktion prüft zuerst eigene Objekte, zeichnet ein privates
Änderungsvorhaben auf, aktualisiert eigene Routen ohne Leeren der Tabelle und
aktualisiert nft-Regeln atomar. Reine DNS-Fehler versuchen eine unterbrechungsfreie
Wiederherstellung. Nach Prozessabbruch setzt der nächste serialisierte Aufruf
das exakte alte/neue Änderungsvorhaben fort, auch nach Schreiben der Unit-Datei
vor systemd daemon-reload. Fremde Objekte/Änderungen werden abgewiesen. Das
Vorhaben erlaubt nie einen Wechsel von Uplink, Quellnetzen oder Datenschutz-UID/
-Phase. IPv6-Fähigkeitswechsel dürfen nur den dedizierten DNS-/RA-Daemon neu
starten; Steuer-WLAN, Tor und Datenverbindungen werden nicht neu gestartet.
Eine vorhandene Steuer-ULA bleibt bis zu ausdrücklichem --off lokal zugeordnet.
Echter Adress-/Linkverlust kann Verbindungen dennoch abbrechen. Internetverfügbarkeit
und vollständige Pi-/Hardwareabnahme werden durch diese Softwareprüfungen nicht
garantiert. CLI auf Englisch; deutsche und englische TXT-Hilfe werden separat paketiert.

## Prüfung

Die gezielten Regressionen in `test_share_watch.py` prüfen stabile Takte,
normale/Tor-DNS-Änderungen, Quellen-/Adress-/Gateway-/Präfixänderungen, unterbrochene
Schreibvorgänge und Befehle, Wiederherstellungsfehler/-fortsetzung, geladenen gegenüber
geschriebenem Unit-Zustand, fremde Objekte, Timerlebenszyklus und alle
Clientquellenkombinationen. Komponentenprüfung ausführen:

```sh
python3 -B kali/tools/components.py check --component share-control
sudo unshare -n python3 kali/pi4/components/share-control/tests/native_watch_check.py
```

Die native Aktualisierungsprüfung benötigt dnsmasq, conntrack, iproute2, nftables
und util-linux. `--tools PATH` darf auf entpackte dnsmasq-/conntrack-Pakete derselben
Distribution zeigen; Hostpakete oder -dienste müssen nicht installiert werden.
Sie verweigert den Host-Namespace und prüft echte DNS-Änderungen, bestehende
Pi-/Client-TCP-Sockets, Wechsel bevorzugter IPv4-/IPv6-Quellen, IPv6-Erscheinen/-Verlust,
eine aktive Alternativroute, Uplink down/up, erhaltenes Steuer-TCP und OFF-Bereinigung.
Netzwerkerkennung und Dienstverwaltung sind explizite lokale Testadapter; der
Tor-Pfad nutzt eine Relay-Fixture mit eigener UID, keinen echten Tor-Circuit.
Client-ULA/-Routen sind statisch; damit sind SLAAC-Empfang, systemd-Sandboxing und
Pi-/Telefonverhalten nicht belegt. Live-Auslösertests sowie 2 Stunden normaler
Betrieb und 2 Stunden echtes Tor folgen getrennt. Frühere datierte Ergebnisse unten
bleiben historische Nachweise, keine Abnahme von Version 0.1.9.

Version 0.1.6 entfernt reservierte Routen vor dem Löschen ihrer bevorzugten
IPv6-Quelladressen. Unterbrochene ältere Bereinigung erkennt ausschließlich die
exakte eigene Steuerroute ohne ihre entfernte Quelle, nachdem deren Abwesenheit
und leere Adresszuständigkeit bestätigt sind; normale Live-Prüfung bleibt streng.
Eigene externe Routen können nach Adressverlust ihre bevorzugte Quelle verlieren,
auch nachdem dieselbe Adresse wiederkehrt. Bereinigung/erneute Anwendung erlaubt
nur diese exakte Auslassung; `linkdown` nur bei tatsächlich ausgefallenem oder
fehlendem ausgewähltem Interface. Andere Routenfelder und Policyregeln bleiben
exakt. Native isolierte veth-Fixtures prüfen Trägerverlust, Adressentfernung und
Wiederverbindung. Die DNS-Startprüfung wiederholt begrenzt, während dnsmasq seine
Rechte abgibt. Sie verlangt vor Weiterleitung die erwartete UID und alle
dedizierten Sockets; ein Timeout führt weiterhin zur Wiederherstellung. Live-Status
wertet eine falsche UID nie als gesund. Beobachtete Fehler und Wiederherstellung
sind durch Fixtures abgedeckt. Nativer Produktivstart und Wiederherstellung
bestanden am 19.10.2026 auf dem Pi mit echtem AWUS036ACM, systemd-DNS-Unit und
Windows-Steuer-WLAN-Client: IPv4-/IPv6-HTTPS mit geprüftem TLS, DNS, RA/SLAAC/RDNSS,
softwareseitige Uplinktrennung, Wiederverbindung/erneute Anwendung und OFF-
Wiederherstellung. Steuergeräte-Sockets waren an WLAN-Interface/-Quelle gebunden,
um das Laptop-LAN auszuschließen. Direktes SSH OFF/ON erhielt Guacamole und
Desktop-/tmux-Prozesse auch bei aktiver Freigabe. Nachweise liegen im lokalen
Builder-Verzeichnis `build/evidence`: `awus-common-egress-audit.json`,
`awus-controller-ipv6-cycle-audit.json` und `component-ssh-disconnect-cycle-share.json`.
Physisches USB-Abziehen, physisches LAN, iPhone-Freigabe und erster Boot eines
neuen Komponentenimages bleiben getrennte Prüfungen.

Das Paket 0.1.6 hat 67 bestandene Offline-Fixtures in drei Läufen und drei
bytegleiche Bauten (SHA256
`a750346d7e7bad6267a4999a31df4d8346cff2bb5ec29fd2a09ca537d01f017a`), einschließlich
IPv6-Adresszuständigkeit/DAD, unterbrochenem globalem Forwarding, Bereinigung
abgezogener Adapter, DNS-UID, abgeschlossener gegenüber fehlgeschlagener Erkennung
und nativer ip-/nft-JSON-Normalisierung. Ein bytegenauer Manifest-Nutzdatei-Smoke-Test
führt --help über den Kernel-Shebang aus und erkennt CRLF-Interpreterzeilen, die
bei über Python gestarteten Tests unbemerkt blieben. Version 0.1.3 behebt diesen
Paketierungsfehler; das gebaute Archiv 0.1.2 bleibt unverändert. Unabhängige Prüfung
fand keinen weiteren konkreten Lebenszyklusblocker. Am 19.10.2026 bestanden in
isolierten Pi-Netzwerk-/Mount-Namespaces IPv4-only- und Dual-Stack-Pakettests mit
dnsmasq 2.93 und nftables 1.1.7: Pi-/Client-TCP-/UDP-Ausgang, echtes UDP-/TCP-DNS,
IPv6-Link-Local-Resolverquellenauswahl, NAT66, Ausfall des gewählten Uplinks ohne
Ausweichweg und exakte OFF-Wiederherstellung. Hostnetz und Produktivdienste blieben
unverändert; das Leaseverzeichnis war schreibgeschützt. Clients nutzten statische
ULA/Routen; der erste Datenpfadtest belegte deshalb keinen RA-Empfang. Ein
gesonderter isolierter A/B-Test fand und bestätigte die fehlende ausdrückliche
RA-Interfacebindung. Mit dieser Bindung erhielt der Client erwartetes RA-Präfix/
RDNSS, lernte SLAAC-Adresse und RA-Standardroute und bestand IPv6-TCP sowie UDP-/
TCP-DNS über den gewählten Link-Local-Resolver. Version 0.1.4 enthält diese
Korrektur. Die endgültige unveränderte Runtime (SHA256
`9de9d794c20f680cbb039f6ae5fe61b4ff4a0cfbf8119077fdc265473f997aa8`) bestand dieselben
isolierten RA/SLAAC/RDNSS- und IPv6-/DNS-Paketprüfungen sowie ihren eigenen
Socketvalidator gegen echte TCP-/UDP-Ausgabe und Prozess-UID. Genau zehn DNS-
Listener waren auf Steuer- und Loopbackadressen begrenzt; Hostzustand blieb
unverändert und Bereinigung schloss ab. Nachweis:
`share-pi-ra-namespace-20261019T185321Z/dual.json` im lokalen Builder-Nachweisverzeichnis.
systemd-Unit-Metadaten waren in dieser isolierten Prüfung simuliert; tatsächliche
systemd-Härtung und reale Telefon-/Upstream-Abnahme bleiben getrennt. Ältere reine
Steuergerätetests aus 0.1.1 zählen nicht als Beleg für diesen Vertrag.

Die optionale IPv4-Policy-Regression wird so ausgeführt:

```sh
sudo unshare -n python3 kali/pi4/components/share-control/tests/namespace_check.py
```

Sie benötigt einen frischen, leeren isolierten Netzwerk-Namespace und verweigert
den Host-Namespace. Sie prüft echte IPv4-Paketpfade, lokale/Client-UDP-DNS-Umleitung,
IPv6-Sperre bei reiner IPv4-Auswahl, Abziehen ohne Ausweichweg und Wiederherstellung.
Sie verwendet einen Echo-Socket statt eines echten DNS-Daemons und ist keine
vollständige Dual-Stack-Abnahme. Sie nutzt lokale Fixtures, keine Internetendpunkte.
Physische Pi-/Telefonabnahme ist getrennt; eine umfassende Hardwarefreigabe wird
hier nicht behauptet.

Primärquellen:

* [dnsmasq-Handbuch](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html):
  Resolver-Interfacebindung, isolierte Konfiguration und RA-/SLAAC-/RDNSS-Optionen.
* [Linux-6.12-IP-sysctls](https://docs.kernel.org/6.12/networking/ip-sysctl.html):
  IPv6-Forwarding und Annahme von Router Advertisements.
* [nftables-Handbuch](https://netfilter.org/projects/nftables/manpage.html): NAT,
  IPv6-Masquerading und atomare Regelaktualisierungen.
* [ip-rule-Handbuch](https://man7.org/linux/man-pages/man8/ip-rule.8.html): lokale
  Eingangsinterfaceauswahl und abschließende unerreichbare Policyrouten.

DNS-Lebenszykluskorrektur in 0.1.10: Linux-bind-dynamic mit ausdrücklicher Loopback-
Tor-Resolverbindung verwenden. Ein echtes NEWADDR-Ereignis vor dem normalen
Wechsel-zu-Tor-HUP zeigte in dnsmasq 2.93 einen veralteten physischen Interfaceindex;
`@lo` allein oder ein alleiniger Wechsel des Bindungsmodus reichte nicht. Der
kombinierte Modus aktualisiert diesen Index bei DNS-Metadatenänderungen ohne
Resolverneustart. Die bisherige Steuer-/Loopback-Listenerauswahl und der
Datenschutz-Guard bleiben erhalten. Native Backend-Fixtures ersetzen keine echte
Tor-/iPhone-Abnahme.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Selected-uplink Internet sharing

Optional `share-control` **0.2.0**, installed with `auto-cli`. Installation does
not activate sharing. The accepted Pi4 v05 network layout is required.

If the owned guest-AP veth disappears, Linux can mark its retained input policy
rule as detached. Cleanup accepts only that exact reserved rule with no live
guest veth and removes it without resolving the missing device name. Live health
validation still rejects it; foreign, modified and duplicate rules remain errors.

The optional anonymity runtime composes exact owned INPUT/OUTPUT admissions
with this policy. While Tor is configured, manual uplink/source changes are
refused; turn that mode off first. Automatic updates of the same selected
uplink use the coordinated refresh path, without restarting/blocking Tor.
Without the optional helper, the ordinary sharing
contract remains unchanged. `PRIVACY_API = 1` prevents incompatible older
sharing packages from being used by the new runtime.

```sh
sudo auto share --wifi [--to wlan0] [--from ctrl0,wlan1]
sudo auto share --lan [--to eth0] [--from ctrl0,wlan1]
sudo auto share --off
sudo auto share --status
auto share --help
```

Bare `auto share` shows status. With multiple eligible uplinks, a TTY lists their
names, connection state and Wi-Fi SSIDs for selection. Without a TTY, specify
`--to`. It always identifies the output/uplink, not the incoming network.
The previous `--interface` remains a compatibility alias; specifying both selectors
is refused before any network operation.
Omitting `--from` always asks which client networks should receive Internet:
`ctrl0` and, while running, the additional AP's physical adapter name. Enter one
name/number or comma-separated choices. No implicit default; Ctrl+C cancels.
Non-interactive use requires `--from NAME[,NAME...]`. An explicit AP name must
currently host the additional AP; ordinary client adapters are uplinks, not
sharing sources. The Pi always follows the selected uplink. Excluded client
networks cannot use forwarding, shared DNS or Tor listeners; local control and
the welcome page remain available. Tor inherits the chosen source networks.
Wi-Fi must be an external USB radio; ctrl0 and its internal radio are excluded.
The selected NetworkManager connection must already have usable IPv4 addressing,
gateway and DNS. IPv6-only uplinks are rejected; NAT64/DNS64 are not implemented.
No uplink connection is established or disconnected by this command.

While active, **this Pi and the selected client networks** use only the selected
uplink. IPv4, available native IPv6 and UDP/TCP DNS follow that choice. No fallback
to another adapter is allowed, including after removal of the chosen adapter.
Existing sockets tied to another uplink may stop working. Local control/loopback
remain accessible. `--off` removes sharing and restores normal Pi routing.

## DNS and IPv6

NetworkManager DNS arrays may contain separate lines or multiple addresses joined
by ` | `. Both IPv4 and IPv6 are parsed and validated before use; malformed
metadata reports a bounded contextual error without asserting that sharing is off.
Link-local scopes must match the selected interface. Version 0.1.5 corrects this
native array format discovered on the guest Wi-Fi; built older archives remain
unchanged. The packet path and RA/service configuration are unchanged from 0.1.4.

A separate dnsmasq process on port 1053, running as the fixed nobody/nogroup
identity, answers local/client DNS and forwards only to the selected DNS servers.
It loads neither resolv.conf nor the main dnsmasq configuration. UDP and TCP DNS
are redirected for the Pi and control clients; exact resolver UID/interface/
server exceptions prevent recursive interception. IPv6 link-local DNS additionally
allows only that UID, selected interface, configured destination and DNS port.
The local pi4 record is retained. Encrypted DNS is not intercepted, but still
follows selected-uplink routing and the egress guard.

The server list lives in a root-owned, non-writable-by-clients runtime file.
dnsmasq re-reads it on SIGHUP, without a process restart. Under Tor, the frontend
uses the local Tor DNS endpoint directly: physical-interface-bound DNS sockets
cannot reliably receive OUTPUT-DNAT loopback replies. The private filter still
forbids direct resolver egress. Turning Tor off reloads the selected, explicitly
bound uplink servers. This requires anonymity-runtime 0.1.6 when Tor is used.

A temporary, tightly scoped INPUT admission allows upstream RA/ND, necessary
ICMPv6 errors, MLD queries and DHCPv6 replies, plus control-side RS/ND. A bounded
router solicitation lets the existing NetworkManager connection discover IPv6.
A global unicast address and usable default route are required. Inspection or
setup errors fail activation; they are not reported as absent IPv6 capability.

When IPv6 is usable, a stable machine-derived ULA /64 and link-local address are
added to ctrl0. dnsmasq advertises that ULA via RA/SLAAC with RDNSS; NAT66 translates
client traffic onto the selected uplink. Prefix delegation is not required.
The RA daemon explicitly admits ctrl0 by interface name; dnsmasq does not use
listen-address entries for its RA interface check. Its added DNS link-local
socket is accepted only with the exact ctrl0 scope. Upstream listeners are refused.
Without usable IPv6 after completed discovery, a terminal unreachable route and
firewall block IPv6 external egress. There is no fallback via another interface.

## Ownership and recovery

* IPv4/IPv6 routing table **17855** and priorities **17853–17856** are reserved.
  Rules select ctrl0 and locally originated traffic (`iif lo`). Exact link-local,
  multicast and DHCP-broadcast rules retain necessary link maintenance. Each
  family has a terminal unreachable default; unknown policy rules are rejected.
  Main default routes and NetworkManager profiles are not rewritten.
* Firewall objects are scoped to `inet auto_share`, one owned Pi4 forwarding
  chain/jump and exact leading INPUT exceptions. The temporary
  `inet auto_share_gate` blocks external output/forwarding during transitions.
  This gate is used for explicit enable/disable/switch, never for automatic
  in-place refresh. All base Pi4 rules, including the current SSH choice, are validated. The final
  INPUT contract is two IPv4 DNS rules, six IPv6 admission rules, and (when active)
  two ULA DNS rules. `auto ssh` validates these exact forms.
* Conntrack mark **0x4155544f** identifies selected/redirected traffic. Stop/switch
  deletes only those mappings; unrelated local/control flows are not flushed.
  Automatic refresh never deletes them. Established owned flows remain limited
  to that same selected interface even when a still-valid old address stops
  being preferred. The Tor transport exception also retains UID, TCP and IPv4
  scope; it does not admit direct application traffic or IPv6 under Tor.
* Per-interface IPv4 and all existing IPv6 forwarding values are saved. IPv6
  global forwarding fans out in Linux, so unrelated interface values are restored
  immediately and again on stop. Removed adapters need no nonexistent sysctl
  restored; new adapters retain their observed value during cleanup.
* IPv6 addresses are recorded as owned only after successful creation. Existing
  equal addresses are refused, never adopted or removed. Duplicate-address
  detection must complete. Stopping sends a zero-lifetime RA before removal;
  if that packet cannot be sent, forwarding is still disabled and a warning is
  printed. Clients may retain an unusable address until its advertised expiry.
* Root-only lock/state and the service unit live under `/run`. Failures and Ctrl+C
  attempt rollback; incomplete cleanup retains the guard/state for `--off`.
  Unknown edits are refused. Failed switches attempt to restore the previous
  usable selection. Uncatchable process/power loss can leave incomplete runtime
  state; the next command reports this rather than assuming success.

Sharing is default-off and expires on reboot. No persistent DHCP/AP/NM configuration
or system resolver file is changed. A runtime-only timer checks local metadata
every 30 seconds. Two consistent observations debounce DNS/address/gateway/IPv6
changes. It never selects another interface/source, performs continuous Internet
probes or imposes a download deadline. An unavailable uplink is reported without
tearing down working state or opening another path.

An in-place transaction validates owned objects first, records a private intent,
updates owned routes without table flushing, and atomically updates nft rules.
DNS-only errors attempt a non-disruptive rollback. A killed process resumes its
exact old/new intent at the next serialized call, including after unit-file
publication but before systemd daemon-reload. Foreign objects/edits are refused.
The intent never authorizes a change of uplink, source networks or privacy UID/
phase. IPv6 capability transitions may restart only the dedicated DNS/RA daemon;
control WLAN, Tor and data connections are not restarted. An existing control
ULA remains locally owned until explicit --off. Real address/link loss can still
break connections. Internet availability and full Pi/hardware acceptance are
not guaranteed by these software checks.
English CLI; German and English TXT help are packaged separately.

## Verification

The focused `test_share_watch.py` regressions cover stable ticks, normal/Tor DNS
changes, source/address/gateway/prefix changes, interrupted writes and commands,
rollback failure/recovery, loaded-versus-written unit state, foreign objects,
timer lifecycle and all client-source combinations. Run the component check:

```sh
python3 -B kali/tools/components.py check --component share-control
sudo unshare -n python3 kali/pi4/components/share-control/tests/native_watch_check.py
```

The native refresh check needs dnsmasq, conntrack, iproute2, nftables and util-linux.
`--tools PATH` may point to extracted matching-distribution dnsmasq/conntrack
packages; no host package/service installation is needed. It refuses the host
namespace and exercises real DNS changes, persistent Pi/client TCP sockets,
preferred IPv4/IPv6 source changes, IPv6 appearance/loss, a live alternate route,
uplink down/up, preserved control TCP and OFF cleanup. Network discovery and
service management are explicit local adapters; the Tor path uses a dedicated-
UID relay fixture, not an actual Tor circuit. Client ULA/routes are static, so
this does not prove SLAAC reception, systemd sandboxing or Pi/phone behavior.
Live trigger tests and 2h normal + 2h real Tor follow separately. Earlier dated
results below remain historical evidence, not acceptance of version 0.1.9.

Version 0.1.6 removes reserved routes before deleting their preferred IPv6
source addresses. Interrupted older cleanup can recognize only the exact owned
control route without its removed source, after confirming that source is absent
and address ownership is empty; normal live validation remains strict. External
owned routes may lose their preferred source after address loss, even after the
same address reconnects. Cleanup/reapply accepts only that exact omission;
`linkdown` is accepted only while the selected interface is actually down or
absent. Other route fields and policy rules remain exact. Native isolated veth
fixtures cover carrier loss, address removal and reconnect. The DNS
startup check has a bounded retry while dnsmasq drops privileges. It requires the
expected UID and all dedicated sockets before forwarding; a timeout still rolls
back. Live status never treats a wrong UID as healthy. The observed failures and
recovery are covered by fixtures. Native production startup and recovery passed
on the Pi on 2026-10-19 with the actual AWUS036ACM, systemd DNS unit and a
Windows control-WLAN client: IPv4/IPv6 HTTPS with verified TLS, DNS, RA/SLAAC/RDNSS,
software uplink disconnect, reconnect/reapply and OFF restoration. Controller
sockets were bound to the Wi-Fi interface/source to exclude the laptop's LAN.
Direct SSH OFF/ON also preserved Guacamole and desktop/tmux processes while
sharing was active. Evidence is kept in the builder's local `build/evidence`
directory: `awus-common-egress-audit.json`, `awus-controller-ipv6-cycle-audit.json`
and `component-ssh-disconnect-cycle-share.json`. Physical USB removal, physical
LAN, iPhone sharing and a new component-image first boot remain separate tests.

The 0.1.6 package has 67 passing offline fixtures in three runs and three
byte-identical builds (SHA256
`a750346d7e7bad6267a4999a31df4d8346cff2bb5ec29fd2a09ca537d01f017a`), including IPv6 address
ownership/DAD, interrupted global forwarding, unplugged adapter cleanup, DNS UID,
completed-versus-failed discovery and native ip/nft JSON normalization. A byte-exact manifest-payload smoke test executes --help through the kernel
shebang, detecting CRLF interpreter lines that Python-invoked tests would miss.
Version 0.1.3 fixes that packaging defect; the built 0.1.2 archive remains
unchanged. Independent
review found no further concrete lifecycle blocker. On 2026-10-19 isolated Pi
network/mount namespaces passed both IPv4-only and dual-stack native packet tests
with dnsmasq 2.93 and nftables 1.1.7: Pi/client TCP/UDP egress, real UDP/TCP DNS,
IPv6 link-local resolver source selection, NAT66, selected-uplink failure with no
fallback, and exact OFF restoration. Host network and production services stayed
unchanged; the lease directory was read-only. The clients used static ULA/routes:
the initial data-path test therefore did not prove RA reception. A separate
isolated A/B test found and confirmed the missing explicit RA interface binding.
With that binding, the client received the expected RA prefix/RDNSS, learned its
SLAAC address and RA default route, and passed IPv6 TCP plus UDP/TCP DNS through
the selected link-local resolver. Version 0.1.4 incorporates that fix. The final
unmodified runtime (SHA256 `9de9d794c20f680cbb039f6ae5fe61b4ff4a0cfbf8119077fdc265473f997aa8`)
passed the same isolated RA/SLAAC/RDNSS and IPv6/DNS packet checks, plus its own
socket validator against real TCP/UDP output and process UID. Exactly ten DNS
listeners were limited to control and loopback addresses; host state was unchanged
and cleanup completed. Evidence: `share-pi-ra-namespace-20261019T185321Z/dual.json`
in the builder's local evidence directory. Systemd unit metadata was stubbed in
that isolated check; actual systemd hardening and real phone/upstream acceptance
remain separate. Do not count older 0.1.1 controller-only tests toward this contract.

The opt-in IPv4-policy regression can be run with:

```sh
sudo unshare -n python3 kali/pi4/components/share-control/tests/namespace_check.py
```

It requires a fresh, empty isolated network namespace and refuses the host
namespace. It checks real IPv4 packet paths, local/client UDP DNS translation,
IPv6 blocking for an IPv4-only selection, unplug/no-fallback and restoration.
It uses an echo socket, not a real DNS daemon, and is not the full dual-stack
acceptance. It uses local fixtures, not Internet endpoints.
Pi/phone physical acceptance is separate; no broad hardware pass is claimed here.

Primary references:

* [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html): resolver
  interface binding, isolated configuration and RA/SLAAC/RDNSS options.
* [Linux 6.12 IP sysctls](https://docs.kernel.org/6.12/networking/ip-sysctl.html):
  IPv6 forwarding and router-advertisement acceptance.
* [nftables manual](https://netfilter.org/projects/nftables/manpage.html): NAT,
  IPv6 masquerading and atomic rule updates.
* [ip-rule manual](https://man7.org/linux/man-pages/man8/ip-rule.8.html): local
  input-interface selection and terminal unreachable policy routes.

DNS lifecycle correction in 0.1.10: use Linux bind-dynamic with an explicit
loopback Tor resolver binding. A real NEWADDR event before the normal-to-Tor
HUP exposed a stale physical interface index in dnsmasq 2.93; merely specifying
`@lo` or changing bind mode separately was insufficient. The combined mode
refreshes that index without a resolver restart on DNS metadata updates.
The existing control/loopback listen selection and privacy guard are retained.
Native backend fixtures do not replace real Tor/iPhone acceptance.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
