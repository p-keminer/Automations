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

`python3 tools/components.py check --component anonymity-runtime` prüft Fixtures
für Lebenszyklus, Unterbrechung, Fehler, fremde Regeln, strikte Dateiprüfung,
Versionskompatibilität und Share-/SSH-Komposition.

Die ausdrückliche native Prüfung benötigt Root, Linux-Netzwerk-Namespaces,
Python 3, iproute2, nftables und util-linux:

```
sudo unshare -n python3 components/anonymity-runtime/tests/namespace_check.py
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
# Build-time dependencies

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
