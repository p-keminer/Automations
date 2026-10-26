<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Tor-Routingkomponente

Optional, standardmäßig nicht ausgewählt; kein eigener CLI-Befehl und keine
Aktivierung bei Installation oder Boot. `auto tor` verwendet diese geprüfte
Runtime. Voraussetzung ist eine gesunde, ausdrücklich über
`auto share --lan` oder `auto share --wifi` ausgewählte Verbindung.

Der Share-Lock serialisiert Änderungen. Die Aktivierung setzt die Paketfilter
und DNS-Umleitung vor dem Dienststart.
Fehler lassen die Sperre bestehen. Tor 0.1.5 kann im Zustand `recovering` nur
seinen Transport und eine privilegierte SOCKS-Prüfung freigeben; normaler
Pi-/Steuergeräteverkehr bleibt bis zur bestätigten Prüfung gesperrt.
Erst ausdrückliches `--off` beendet den Dienst,
entfernt die eigenen Regeln und kehrt zum vorherigen Share-Pfad zurück. Der
Share-Uplink kann währenddessen nicht gewechselt oder ausgeschaltet werden.
Guacamole, Loopback-SSH und Zugriff im Steuernetz bleiben lokal.

Kann schon der Kernel-/nft-Aufruf keine Sperre installieren oder deren Zustand
nicht mehr verifiziert werden, meldet die Runtime ausdrücklich einen nicht
verifizierten Guard. In diesem Fehlerfall ist eine Sperrwirkung nicht bewiesen.

Nur der jeweilige dedizierte Transportbenutzer darf TCP über den gewählten
Ausgang senden. Direkte DNS-Ausleitung, sonstiges externes UDP/QUIC und ICMP
werden gesperrt; notwendige DHCP-/IPv6-Linkverwaltung bleibt erhalten. Die
vorhandene DNS-Frontend-Instanz beantwortet weiterhin `pi4` und sendet RA/RDNSS.
Mit Tor nutzt sie dessen lokalen DNS-Port direkt; der Guard sperrt weiterhin
jede direkte DNS-Ausleitung. Beim Ausschalten wird ihre gebundene Uplink-
Resolverliste ohne Prozessneustart wiederhergestellt.
Tor verwendet IPv4-TCP und
UDP-DNS; externe IPv6-Anwendungen und TCP-DNS zum Tor-Backend bleiben gesperrt.

Die Runtime prüft vor Aktivierung `PRIVACY_API = 1` und `PRIVACY_DNS_API = 1`
in share-control (ab 0.1.9) und, falls installiert, ssh-control (ab 0.1.5). Alte Archive werden dadurch nicht
still mit inkompatiblen Firewall-Guards kombiniert. Ohne diese optionale
Komponente bleiben die Grundfunktionen eigenständig nutzbar.

## Lokale Prüfung

`python3 kali/tools/components.py check --component anonymity-runtime` prüft Fixtures
für Lebenszyklus, Unterbrechung, Fehler, fremde Regeln, strikte Dateiprüfung,
Versionskompatibilität und Share-/SSH-Komposition.

Die ausdrückliche native Prüfung benötigt Root, Linux-Netzwerk-Namespaces,
Python 3, iproute2, nftables und util-linux:

```
sudo unshare -n python3 kali/pi4/components/anonymity-runtime/tests/namespace_check.py
```

Sie verweigert den Host-Netzwerkraum und nicht leere Ausgangsräume. Alle Links,
Routen, Filter und Testserver liegen in eigenen temporären Netzwerk-Namespaces.
Geprüft werden die native nft-JSON-Rücklesung und echte IPv4/IPv6-TCP-/DNS-Pakete,
UID-Ausnahmen, Backend-/Uplinkverlust, kein Fallback und Rückkehr zum Share-Pfad.
Lokale kontrollierte Echo-Backends ersetzen dabei den echten Tor-Transport: dies ist
kein Nachweis echter Anonymität, öffentlicher Dienste oder Pi-Hardware. Falls
conntrack vorhanden ist, wird das Löschen eigener markierter Flows ausgeführt;
ohne das Programm nennt der Test diese Grenze ausdrücklich. Keine Downloads.

Der tatsächliche Transportdienst, Tor-Ausgangsprüfungen und dessen
Eigentümerprüfungen gehören zu `tor-control`.

Der frühere Proxy-Prototyp bleibt lokal und wird weder versioniert noch gebaut.
Die interne Kompatibilität mit bereits installierten Versuchen bleibt erhalten;
diese Runtime liefert selbst keinen Proxy-Transport, Dienst oder CLI-Befehl.
Version 0.1.2 ändert nur Katalogbeschreibung und Hilfe, nicht die Routinglogik.
Version 0.1.3 ergänzt die geschlossene Tor-Start-/Wiederherstellungsphase und
den Rückbau eines Regelwechsels, falls das Schreiben des neuen Zustands scheitert.

## Abhängigkeiten beim Bau

Der Imagebuilder benötigt `auto-cli >= 0.1.3` und `share-control >= 0.1.9`.
`ssh-control` ist optional; bei gemeinsamer Auswahl ist mindestens 0.1.5 nötig.
Diese Manifestvorgaben werden vor Paketdownload oder Imagearbeiten geprüft.
Der Laufzeitschutz prüft die installierte Integration weiterhin vor der Aktivierung.

Version 0.1.5 übersetzt ausschließlich die geprüften Betriebsfehler des
vertrauenswürdigen Share-Moduls an der Grenze zur serialisierten Operation.
Sperrkonflikte und Validierungsablehnungen behalten ihre hilfreichen Meldungen,
ohne beliebige Ausnahmedaten offenzulegen. Vor Operationsbeginn ändern sie weiterhin
weder Routing noch Zustand; bei Fehlern innerhalb einer aktiven Operation bleibt
der bestehende Schutz mit Sperrwirkung erhalten.

Version 0.1.6 koordiniert die Aktualisierung von Share-Metadaten im laufenden
Tor-Betrieb ohne vorsorgliche Sperrphase oder Tor-Neustart. Bestehende Transport-
TCP-Verbindungen bleiben auf dessen UID, das ausgewählte Interface und IPv4
beschränkt, solange ihre Quelladresse gültig bleibt. DNS-Frontend-Reloads verwenden
den lokalen Tor-Endpunkt und vermeiden die Kombination aus physischer
Interfacebindung und Loopback-DNAT. Ein atomares Guard-Update erhält die
Datenschutzphase; unterbrochene Veröffentlichungen werden aus dem geschützten
Share-Änderungsvorhaben wiederhergestellt. Der native Aktualisierungstest von
share-control prüft echte Resolver-/TCP-Pakete. Dies ist Softwarevalidierung;
Live-Auslöser und Dauerlaufabnahme mit Pi/Telefon bleiben getrennt.
Proxyexperimente bleiben vom Paketbau ausgeschlossen.

Version 0.1.7 unterscheidet eine bereits vor Operationsbeginn belegte Share-Sperre
von späteren Fehlern. Der interne Tor-Wiederherstellungstakt darf nur den ersten
Fall zurückstellen; Operationsfehler behalten ihre Guard-/Fehlerbehandlung.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Tor routing component

Optional and unselected by default; no separate CLI command and no activation
during installation or boot. `auto tor` uses this validated runtime. It requires
a healthy connection explicitly selected with `auto share --lan` or
`auto share --wifi`.

The Share lock serializes changes. Activation installs packet filters and DNS
redirection before starting the service. Failures leave blocking in place.
In the `recovering` state, Tor 0.1.5 can admit only its transport and a privileged
SOCKS check; ordinary Pi/controller traffic stays blocked until verification
succeeds. Only explicit `--off` stops the service, removes its owned rules and
returns to the previous Share path. The Share uplink cannot be changed or disabled
while this is active. Guacamole, loopback SSH and control-network access remain local.

If the kernel/nft call cannot install blocking or its state can no longer be
verified, the runtime explicitly reports an unverified guard. Blocking is not
proven in that failure case.

Only the dedicated transport user may send TCP through the selected output.
Direct DNS egress, other external UDP/QUIC and ICMP are blocked; necessary
DHCP/IPv6 link management remains available. The existing DNS frontend still
answers `pi4` and sends RA/RDNSS. Under Tor it uses Tor's local DNS port directly;
the guard continues blocking all direct DNS egress. Turning Tor off restores its
interface-bound uplink resolver list without restarting the process. Tor uses
IPv4 TCP and UDP DNS; external IPv6 applications and TCP DNS to the Tor backend
remain blocked.

Before activation the runtime checks `PRIVACY_API = 1` and `PRIVACY_DNS_API = 1`
in share-control (from 0.1.9) and, if installed, ssh-control (from 0.1.5).
This prevents silently combining old archives with incompatible firewall guards.
Without this optional component, the basic functions remain independently usable.

## Local checks

`python3 kali/tools/components.py check --component anonymity-runtime` checks
fixtures for lifecycle, interruption, failures, foreign rules, strict file checks,
version compatibility and Share/SSH composition.

The explicit native check requires root, Linux network namespaces, Python 3,
iproute2, nftables and util-linux:

```
sudo unshare -n python3 kali/pi4/components/anonymity-runtime/tests/namespace_check.py
```

It refuses the host network namespace and nonempty starting namespaces. All
links, routes, filters and test servers stay in dedicated temporary network
namespaces. Checks cover native nft JSON readback, real IPv4/IPv6 TCP/DNS packets,
UID exceptions, backend/uplink loss, no fallback and return to the Share path.
Controlled local echo backends replace the actual Tor transport; this does not
prove real anonymity, public services or Pi hardware. If conntrack is available,
deletion of owned marked flows is exercised; otherwise the test explicitly names
that limitation. No downloads.

The actual transport service, Tor exit verification and its ownership checks
belong to `tor-control`.

The former proxy prototype remains local and is neither versioned nor packaged.
Internal compatibility with previously installed experiments is retained; this
runtime itself provides no proxy transport, service or CLI command.
Version 0.1.2 changes only the catalog description and help, not routing logic.
Version 0.1.3 adds the closed Tor startup/recovery phase and rolls back a rule
change if writing the new state fails.

## Build-time dependencies

The image builder requires `auto-cli >= 0.1.3` and `share-control >= 0.1.9`.
`ssh-control` is optional; when selected together, it must be at least 0.1.5.
These manifest constraints are checked before package download or image work.
The runtime guard still verifies the installed integration before activation.

Version 0.1.5 translates only the trusted sharing module's audited operational
errors at the serialized operation boundary. Lock contention and validation
refusals retain their useful messages without disclosing arbitrary exceptions.
They still cause no routing/state mutation before the operation begins; errors
inside an active operation retain the existing fail-closed guard behavior.

Version 0.1.6 coordinates in-place Share metadata refresh under Tor, without a
preventive blocked phase or Tor restart. Existing transport TCP remains limited
to its UID, selected interface and IPv4 family while its source remains valid.
DNS frontend reloads use the local Tor endpoint, avoiding physical-interface
binding combined with loopback DNAT. An atomic guard update preserves the privacy
phase; interrupted publications are recovered from the protected Share intent.
See share-control's native refresh check for real resolver/TCP packet coverage.
This is software validation; live Pi/phone trigger and duration acceptance remain
separate. Proxy experiments remain excluded from packaging.


Version 0.1.7 distinguishes a held Share lock before entering an operation from later failures. The internal Tor recovery tick may defer only the former; operation failures retain guard/error handling.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
