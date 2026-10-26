<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Tor steuern

Optionales Modul `auto tor` für das verwaltete Pi4-Image. `anonymity-runtime` und
dessen Abhängigkeiten ebenfalls auswählen. Die Installation aktiviert Tor nicht
und ändert kein Routing. Der Imagebuilder maskiert die Tor-Diensteinheiten der
Distribution; nur der separate Dienst `automations-tor.service` wird bei
ausdrücklichem `--on` verwendet.

## Befehle

- `sudo auto tor --on`: benötigt einen gesunden, ausdrücklich mit `auto share`
  ausgewählten Uplink. Die gemeinsame Runtime sperrt direkte Ausweichwege, bevor
  der dedizierte Tor-Client startet. Eine TLS-Anfrage über dessen lokalen
  SOCKS-Endpunkt muss vor Abschluss der Aktivierung `IsTor: true` melden.
- `sudo auto tor --off`: stoppt Tor, bevor der bestehende Share-Pfad wiederhergestellt wird.
- `sudo auto tor --status` und Aufruf ohne Argument: zeigen den Routingzustand und
  fragen die öffentliche IP frisch über den aktuell erzwungenen Pfad ab. Keine Routenänderung.
- `sudo auto tor --rotate`: fordert neue Tor-Circuits für neue Verbindungen an,
  wartet auf das Aktionsereignis und meldet die aktuell beobachtete öffentliche IP.
- `sudo auto tor --rotate-every 10m`: plant Rotation in Intervallen von `30s` bis
  `24h` mit ganzzahligen `s`, `m` oder `h`. Auch zusammen mit `--on` unterstützt.
- `sudo auto tor --rotation-off`: beendet den Zeitplan, lässt Tor aber aktiv.
- `sudo auto tor --check`: lädt die Exit-Liste frisch, validiert und ersetzt sie
  atomar, misst die aktuelle öffentliche IP und meldet `VERIFIED` oder `NOT LISTED`.
- `sudo auto tor --check --ip 1.1.1.1`: frische Liste, explizite öffentliche IP,
  keine Abfrage der eigenen IP. Eine IPv6-Adresse führt nach der Aktualisierung
  zu einem ausdrücklichen Fehler wegen fehlender Abdeckung.
- `sudo auto tor --check --status`: normaler Status und aktuelle IP sowie Pfad/
  Metadaten der gespeicherten Liste. Kein Download und keine Zugehörigkeitsprüfung.
- `auto tor --help`: englische Hilfe ohne privilegierten Zugriff oder Netzwerkzugriff.

## Transportgrenzen

Tor- und Proxy-Modus schließen sich gegenseitig aus. Wechsel oder Ausschalten von
Share werden abgewiesen, bis der Datenschutzmodus ausdrücklich deaktiviert wurde.
Die Aktivierung gilt bis zum Neustart; es gibt keinen Autostart. Geplante Rotation
ist standardmäßig aus. Fehlgeschlagener Start oder Verlust des Tor-Dienstes lassen
betroffenen Verkehr ohne direkten Ausweichweg gesperrt. Lokaler Steuer-AP,
Guacamole sowie Share-DNS und lokaler Name `pi4` bleiben erhalten.

`--on` startet auch den optionalen Wiederherstellungstimer. Ein ausgefallener
Tor-Daemon startet hinter einer geschlossenen Sperre für Anwendungsverkehr neu.
Nur das Tor-Konto darf Relays kontaktieren; eine feste SOCKS-/HTTPS-Prüfung nur für
Root muss Tor bestätigen, bevor normaler Pi- und Steuergeräteverkehr wieder
zugelassen wird. Fehlgeschlagene Prüfungen werden nach zehn Sekunden wiederholt.
Bereitschaft ist unter der Share-Sperre an denselben systemd-Aufruf und Guard
gebunden; eine alte Prüfung kann weder `--off` aufheben noch einen neueren
ungeprüften Daemon freigeben. `--off` beendet den Timer und stellt den vorherigen
Share-Pfad ausdrücklich wieder her. Keine Wiederherstellungs-Unit wird beim Boot
aktiviert. Ein fehlender oder geänderter Uplink wird nie still ersetzt; eine
ungeprüfte Firewall wird gemeldet statt überschrieben. Externe Anwendungen müssen
sich nach einem Daemonfehler möglicherweise neu verbinden.

Das getrennte Konto `auto-tor` betreibt einen IPv4-Tor-Client. Transparentes IPv4-TCP
verwendet Port 19040 auf Loopback und der festen Steueradresse; lokale SOCKS-Prüfungen
nutzen 127.0.0.1:19050. Tor-DNS verwendet UDP-Port 19053 auf IPv4-/IPv6-Loopback über
den bestehenden Share-Resolver. Tors DNSPort unterstützt nur A/AAAA/PTR. Ausgehendes
DNS-TCP, sonstiges UDP, ICMP und externes Anwendungs-IPv6 sind gesperrt. Anwendungen,
die diese Protokolle benötigen, können scheitern; dies ist kein VPN für alle
Protokolle. Diese Grenzen sind beabsichtigt und dürfen nicht als erfolgreicher
Transport beschrieben werden.

Die gemeinsame Runtime verwaltet Firewall, Routing, Sperre und Zustand. Dieses
Modul verwaltet nur sein festes Tor-Konto, das vom Paket gelieferte Programm,
festen Dienst/Konfiguration und Exit-Prüfung. Unit-/Konfigurationsänderungen
außerhalb der unterstützten Definition werden abgewiesen.

## Rotation

Rotation sendet `SIGNAL NEWNYM` über den Unix-Socket des lokalen
Steuerverzeichnisses mit Modus 0700 und SAFECOOKIE-Authentifizierung einschließlich
Server-HMAC-Prüfung. Tor wird weder neu gestartet noch werden Firewall/Routing
verändert. Die gemeinsame Rotationssperre erzwingt mindestens zehn Sekunden
zwischen bestätigten Aktionen; Tor kann Anfragen unabhängig davon verzögern oder
ignorieren. Die Befehlsbestätigung `250 OK` allein reicht nicht: Das Aktionsereignis
`650 SIGNAL NEWNYM` muss innerhalb der begrenzten Wartezeit eintreffen. Ein lokaler
Ratenbegrenzungsfehler lässt die bestehende Route unverändert.

Scheitert nach bestätigter Rotation nur die Beobachtung der öffentlichen IP,
meldet der Befehl den Fehler, ohne eine ansonsten verifizierte aktive Route zu
sperren. Die Operationssperre bleibt während der Beobachtung gehalten; Guard,
Uplink und unveränderter Tor-Dienstaufruf werden vor dem Erhalt erneut geprüft.
Eine Antwort ohne Tor-Nutzung oder eine tatsächliche Zustandsänderung führt
weiterhin zur Sperre. Dieselbe Regel gilt für wiederholtes `--on` bei bereits
gesundem aktivem Modus.

NEWNYM trennt neue Streams von alten Circuits und leert Tors DNS-Cache. Bestehende
TCP-Verbindungen werden nicht beendet. Eine andere Exit-IP ist **nicht garantiert**.
Eine manuelle Anfrage zeigt die gemessene IP auch dann, wenn sie unverändert ist.
Geplante Anfragen laufen still unter `auto-tor` und protokollieren nur Fehler im
festen transienten Dienst `automations-tor-rotation.service`. Dieser Worker ist
an den Wiederherstellungstimer gebunden, übersteht die Tor-Daemon-Wiederherstellung,
wartet vor der ersten Anfrage ein Intervall und wird durch `--rotation-off` und
`--off` gestoppt. Er hat nur AF_UNIX-Zugriff, keine Netzwerksockets. Kein Zeitplan
wird beim Boot automatisch aktiviert; wiederholtes `--on` erhält einen bestehenden
gesunden Zeitplan, sofern kein neues Intervall ausdrücklich angegeben wird.

## Vorgaben für die frische Exit-Liste

Feste Endpunkte, normale System-CA-Prüfung, keine Weiterleitungen,
keine Proxy-Umgebungsvariablen und keine benutzerdefinierten URLs:

- `https://check.torproject.org/exit-addresses` (TorDNSEL-Format mit Zeitstempeln).
- `https://check.torproject.org/api/ip` (beobachtete IP und `IsTor`-Flag der Anfrage).

Jede echte Prüfung lädt erneut; bei Fehlern gibt es keinen Rückgriff auf einen
Listencache. Downloadfehler enthalten den geprüften Transportfehler, etwa
Gesamtzeitlimit oder TLS-Prüffehler, ohne beliebige Ausnahmedaten offenzulegen.
Die einzige dauerhafte Liste ist `/var/lib/automations/tor-exits.json`: ein
normalisierter Datensatz mit Quell-URL, Quell-/Downloadzeiten, Rohdaten-SHA256 und
deduplizierten Adressen. Eine temporäre Datei wird per fsync gesichert und erst
nach Validierung atomar ersetzt; temporäre Dateien werden bei Fehlern entfernt.
Ein Download-/Parsefehler erhält die vorherige Datei zur Statusprüfung, verwendet
sie aber nie für die Zugehörigkeitsprüfung. Es entstehen keine datierten Archive
oder zusätzlichen Listenversionen.

Lokale Validierungsgrenzen sind 4 MiB, 25.000 Relay-Datensätze und 128 Adressen je
Relay. Fehlerhafte, leere oder unbekannte Datensätze, nicht öffentliche IPs und
Zeitstempel mehr als fünf Minuten in der Zukunft führen zu Fehlern. Der neueste
`LastStatus` darf höchstens sechs Stunden alt sein; behalten werden nur Adressen,
die innerhalb von 24 Stunden an einem Relay mit Status innerhalb von 24 Stunden
beobachtet wurden. Das sind ausdrückliche lokale Annahmegrenzen, keine
Vollständigkeitsgarantien von Tor. Bei doppelten IPs bleibt die jüngste Beobachtung.

Die Quelle gilt ausschließlich als **beobachtete IPv4-Exits**, nicht als
vollständige IPv6-Exit-Liste. Fehlende IPv6-Abdeckung ist ein Fehler, niemals
`NOT LISTED`. `VERIFIED` belegt nur die Zugehörigkeit zu dieser frisch beobachteten
Menge. `NOT LISTED` beweist nicht, dass Tor ungenutzt war. Keines der Ergebnisse
beweist den Weg jedes Programms/Clients. Normaler Status misst den aktuellen Pfad
auch bei ausgeschaltetem Tor ausdrücklich über IPv4, passend zum implementierten
Transport und zur Listenabdeckung. Scheitert diese Anfrage, gibt es keinen
SOCKS- oder direkten Ausweichversuch. Die SOCKS-Prüfung beim anfänglichen Bootstrap
ist backendbezogen und wird gesondert gekennzeichnet.

## Prüfung

Komponententests nutzen ausschließlich lokale Fixtures und Simulationen:
Quellalter/Adressfamilie/Format, wiederholten Download, keinen veralteten Rückgriff,
Ersetzungsfehler, CLI-Trennung, feste Tor-Konfiguration, Wiederherstellungsfehler
und paralleles OFF/neue Aktivierung. Echte Pi-Abnahme wird getrennt im
Builder-Testplan festgehalten.

Primärquellen:

- [TorDNSEL-Format und Bedeutung der Beobachtung](https://metrics.torproject.org/collector.html#type-tordnsel)
- [Tor-Client-/DNSPort-/TransPort-Optionen](https://manpages.debian.org/trixie/tor/tor.1.en.html)
- [Check-/API-Beispiel des Tor-Projekts](https://archive.torproject.org/websites/lists.torproject.org/pipermail/tor-dev/2017-November/012609.html)
- [Tor-Protokollgrenzen](https://spec.torproject.org/socks-extensions.html)
- [NEWNYM- und SAFECOOKIE-Steuerbefehle](https://spec.torproject.org/control-spec/commands.html)
- [Semantik von Aktionsereignissen und Ratenbegrenzung](https://spec.torproject.org/control-spec/replies.html#signal-received)
- [Warum ein neuer Circuit nicht zwingend die IP ändert](https://stem.torproject.org/faq.html)

Version 0.1.1 meldet bekannte Fehler der validierten gemeinsamen Runtime direkt,
einschließlich des erforderlichen gesunden Share-Uplinks. Unerwartete
Ausnahmedetails bleiben verborgen; Routing, Aktivierung und Rotation sind unverändert.

Version 0.1.2 liest HTTPS-Antwortkörper nach HTTP/1.0- oder `Connection: close`-
Antworten, ohne auf den geschlossenen Verbindungssocket zuzugreifen. Der
Anfrage-Worker unter derselben UID erzwingt weiterhin Gesamtzeitlimit, Größenlimit
und geprüftes TLS. Eine echte lokale HTTPS-Regression prüft den aktuellen Pfad
und den bereitgestellten SOCKS-Transport.

Version 0.1.3 wiederholt die beiden festen HTTPS-GETs bei Transport-Reset, EOF oder
Timeout höchstens dreimal, jeweils mit neuer Verbindung innerhalb des ursprünglichen
Gesamtzeitlimits. Zertifikats-, HTTP-Status- und Antwortvalidierungsfehler werden
nie wiederholt.

Version 0.1.9 wiederholt zusätzlich vorübergehende DNS-Auflösungsfehler und durch
Transportabbruch gekürzte Antwortkörper innerhalb desselben ursprünglichen
20-Sekunden-Gesamtlimits. Kein Timeout wurde erhöht; ein hängender Versuch kann
weiterhin das ganze Budget verbrauchen. Zeitlimitfehler nennen die aktuelle feste
Phase: DNS, TCP, SOCKS, TLS, Anfrageschreiben, Antwortkopf oder -körper. Der Worker
teilt nur eine Phasennummer, keine Namen, URLs, Zugangsdaten oder Antwortinhalte.
Geprüftes TLS, feste Endpunkte, Antwortgrenzen und Messung des aktuellen Pfads
bleiben unverändert. Diese Diagnose-/Wiederholungsverbesserung belegt nicht die
Ursache aller öffentlichen Tor-Streamfehler. Benötigt anonymity-runtime 0.1.5,
damit geprüfte Share-Sperrfehler über die unterstützte Runtime-Fehlergrenze statt
als generische Ausnahme gemeldet werden.

Version 0.1.11 erhöht auf Benutzerwunsch das standardmäßige HTTPS-Prüfzeitlimit
von 20 auf 40 Sekunden. Es gilt für jede normale Exit-Listen- oder öffentliche
IP-Prüfanfrage einschließlich ihrer Transportversuche und vollständigen Antwort.
Getrennte Start-/Wiederherstellungsprüfungen behalten ihre ausdrücklichen
10-Sekunden-Budgets. Diese Prüflimits begrenzen weder normale Browserdownloads
noch Videowiedergabe über Tor. Der abgeschlossene v07-Dauerlauf nutzte 0.1.10;
diese spätere Änderung ist kein neues Dauerlaufergebnis.

Version 0.1.10 verwendet gewöhnliche Tor-Circuits mit `ConfluxEnabled 0`. Das
deaktiviert optionale Circuit-Bündelung, nicht Tor-Routing oder TLS-Prüfung. Auf
dem Test-Pi vermieden frische Starts damit die langen Stillstände transparenter
Streams, die mit dem Standard `auto` auftraten. Das ist ein begrenzter
Live-Vergleich, kein Beweis für einen allgemeinen Conflux-Fehler oder eine Garantie
für jeden Exit. Das ursprüngliche HTTPS-Gesamtlimit und Routing mit Sperre im
Fehlerfall bleiben unverändert. Der Imagebuilder bindet das geprüfte ARM64-Paket
des Tor-Projekts und dessen Archivsignierschlüssel separat fest ein; das
Komponentenarchiv selbst ergänzt kein APT-Repository auf dem laufenden Pi.

Version 0.1.5 benötigt anonymity-runtime 0.1.3 und ergänzt geschützte automatische
Wiederherstellung. Tors Laufzeitverzeichnis übersteht einen Daemon-Neustart, sodass
der isolierte Rotations-Worker den aktuellen SAFECOOKIE-Socket weiterhin sieht.

Version 0.1.6 gibt der Wiederherstellungs-Sandbox CAP_SYS_PTRACE ausschließlich
für die bestehende `ss`-Eigentümerprüfung der Sockets des gemeinsamen DNS-Prozesses.
Die übrigen Sandboxgrenzen bleiben bestehen. Drei echte Daemon-Abstürze wurden auf
dem Test-Pi nach etwa 17, 25 und 26 Sekunden automatisch behoben, einschließlich
Wiederholungen nach fehlgeschlagenen Bereitschaftsprüfungen. Pi- und physische
Steuer-WLAN-Pfade waren währenddessen gesperrt und meldeten danach Tor; lokale
Sitzungen und der Rotations-Worker blieben erhalten. Dies ist eine begrenzte
Live-Abnahme, keine Zusicherung einer Wiederherstellungszeit oder ununterbrochener
externer TCP-Verbindungen.

Version 0.1.12 verschiebt einen internen Wiederherstellungstakt bei typisiertem
Sperrkonflikt der Runtime vor Operationsbeginn. Öffentliche Befehle und tatsächliche
Operations-/Prüffehler melden weiterhin Fehler; Zeitlimits und Verkehrsregeln bleiben gleich.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Tor control

Optional `auto tor` module for the managed Pi4 image. Select `anonymity-runtime`
and its dependencies too. Installing this component does not enable Tor or
change routing. The image builder masks the distribution's Tor service units;
only the separate `automations-tor.service` is used on an explicit `--on`.

## Commands

- `sudo auto tor --on`: requires a healthy, explicitly selected `auto share`
  uplink. The common runtime closes direct fallback before the dedicated Tor
  client starts. A TLS request through its local SOCKS endpoint must report
  `IsTor: true` before activation completes.
- `sudo auto tor --off`: stop Tor before restoring the existing share path.
- `sudo auto tor --status` (also the bare command): show routing state and make
  a fresh public-IP request through the currently enforced path. No route change.
- `sudo auto tor --rotate`: ask Tor for clean circuits for new connections, wait
  for its action event, then report the currently observed public IP.
- `sudo auto tor --rotate-every 10m`: schedule rotation, with intervals from
  `30s` to `24h` using integer `s`, `m`, or `h`. Also supported with `--on`.
- `sudo auto tor --rotation-off`: stop the schedule while leaving Tor active.
- `sudo auto tor --check`: freshly fetch, validate and atomically replace the
  exit list; measure the current public IP; print `VERIFIED` or `NOT LISTED`.
- `sudo auto tor --check --ip 1.1.1.1`: fresh list, explicit public IP, no own-IP
  lookup. An IPv6 address produces an explicit coverage error after the refresh.
- `sudo auto tor --check --status`: ordinary status and current IP plus the
  stored list path/metadata. No exit-list download and no membership check.
- `auto tor --help`: English help, no privilege or network access.

## Transport boundaries

Tor and proxy mode are mutually exclusive. Share switching/off is rejected
until the privacy mode is explicitly disabled. Activation lasts until reboot;
there is no automatic startup. Scheduled rotation defaults to off. A failed start
or lost Tor service leaves affected traffic blocked, without a direct fallback.
The local control AP, Guacamole and the share DNS service/local `pi4` name remain.

`--on` also starts the optional recovery timer. A lost Tor daemon is restarted
behind a closed application-traffic gate. Only Tor's account may contact relays;
a fixed, root-only SOCKS/HTTPS check must confirm Tor before ordinary Pi and
controller traffic is admitted again. Failed checks retry after ten seconds.
Readiness is tied to the same systemd invocation and guard under the share lock;
an old check cannot undo `--off` or release a newer, untested daemon.
`--off` cancels the timer and restores the previous share path explicitly.
No recovery unit is enabled on boot. An unavailable or changed uplink is never
silently replaced; an unverified firewall is reported rather than overwritten.
External applications may need to reconnect after a daemon failure.

The separate `auto-tor` account runs an IPv4 Tor client. Transparent IPv4 TCP
uses port 19040 on loopback and the fixed control address; local SOCKS checks
use 127.0.0.1:19050. Tor DNS uses UDP port 19053 on IPv4/IPv6 loopback through
the existing share resolver. Tor's DNSPort supports A/AAAA/PTR only. DNS TCP
upstream, other UDP, ICMP and external application IPv6 are blocked. Applications
requiring those protocols may fail; this is not an all-protocol VPN. These
limits are intentional and must not be described as successful transport.

The shared runtime owns firewall/routing/lock/state. This module owns only its
fixed Tor account, package-provided executable, fixed service/config, and exit
verification. Unit/config changes outside the supported definition are rejected.

## Rotation

Rotation sends `SIGNAL NEWNYM` through the local mode-0700 control directory's
Unix socket using SAFECOOKIE authentication, including verification of the
server HMAC. It never restarts Tor or changes firewall/routing. The common
rotation lock enforces at least ten seconds between confirmed actions; Tor may
defer/ignore requests independently. A `250 OK` command acknowledgment alone
is insufficient: the `650 SIGNAL NEWNYM` action event must arrive within the
bounded wait. A local rate-limit error leaves the existing route untouched.

If only the public-IP observation after a confirmed rotation fails, the command
reports that failure without blocking an otherwise verified active route. The
operation lock remains held throughout the observation; the guard, selected
uplink and unchanged Tor service invocation are rechecked before preserving it.
A response reporting non-Tor use or an actual state change still fails closed.
Repeating `--on` for an already healthy active mode follows the same rule.

NEWNYM isolates new streams from old circuits and clears Tor's DNS cache.
Existing TCP connections are not terminated. A different exit IP is **not
guaranteed**. A manual request prints the measured IP, even if it is unchanged.
Scheduled requests run silently under `auto-tor`, logging errors only, in the
fixed transient `automations-tor-rotation.service`. That worker is bound to the
recovery timer, survives Tor daemon recovery, waits one interval before its
first request, and is stopped by `--rotation-off` and `--off`. It has only
AF_UNIX access, not network sockets.
No schedule is enabled automatically at boot; repeating `--on` preserves an
existing healthy schedule unless an explicit new interval is supplied.

## Fresh exit-list contract

Fixed endpoints, standard system CA validation, no redirects, no proxy
environment variables, no user-supplied URLs:

- `https://check.torproject.org/exit-addresses` (timestamped TorDNSEL format).
- `https://check.torproject.org/api/ip` (observed IP and request's `IsTor` flag).

Every real check fetches again; there is no cached-list fallback on failure.
Download failures include the audited transport error (for example the total
deadline or TLS verification failure), without exposing arbitrary exception data.
The sole persistent list is `/var/lib/automations/tor-exits.json`, a normalized
record of source URL, source/download times, raw SHA256 and deduplicated addresses.
A temporary file is fsynced and atomically replaced only after validation;
temporary files are removed on failure. A failed download/parse preserves the
previous file for status inspection but never checks against it. No dated
archives or companion list versions are created.

Local validation limits are 4 MiB, 25,000 relay records and 128 addresses per
relay. Malformed/empty/unknown records, non-public IPs and timestamps over five
minutes in the future fail. The newest `LastStatus` must be at most six hours
old; only addresses observed within 24 hours on a relay with status within
24 hours are retained. These are explicit local acceptance limits, not Tor
guarantees about completeness. Duplicate IPs retain their latest observation.

This source is treated strictly as **observed IPv4 exits**, not an exhaustive
IPv6 exit inventory. Missing IPv6 coverage is an error, never `NOT LISTED`.
`VERIFIED` establishes membership in that fresh observed set only. `NOT LISTED`
does not prove that Tor was not used. Neither result proves the route of every
program/client. Normal status measures the current path, including when Tor is
off, explicitly using IPv4 to match the implemented Tor transport and list
coverage; no SOCKS or direct fallback is attempted if that request fails. Initial
bootstrap's SOCKS check is backend-specific and is labeled separately.

## Validation

Component tests use local fixtures and fakes only: source-age/family/format
validation, repeat download, no stale fallback, replacement failures, CLI
separation, fixed Tor configuration, recovery failures and concurrent OFF/new
activation. Actual Pi acceptance is recorded separately in the builder test plan.

Primary references:

- [TorDNSEL format and observation meaning](https://metrics.torproject.org/collector.html#type-tordnsel)
- [Tor client/DNSPort/TransPort options](https://manpages.debian.org/trixie/tor/tor.1.en.html)
- [Tor Project check/API example](https://archive.torproject.org/websites/lists.torproject.org/pipermail/tor-dev/2017-November/012609.html)
- [Tor protocol limitations](https://spec.torproject.org/socks-extensions.html)
- [NEWNYM and SAFECOOKIE control commands](https://spec.torproject.org/control-spec/commands.html)
- [Action-event/rate-limit semantics](https://spec.torproject.org/control-spec/replies.html#signal-received)
- [Why a new circuit need not change the IP](https://stem.torproject.org/faq.html)

Version 0.1.1 reports known errors from the validated shared runtime directly,
including the required healthy share uplink. Unexpected exception details remain
hidden; routing, activation and rotation behavior are unchanged.

Version 0.1.2 reads HTTPS bodies after HTTP/1.0 or `Connection: close` replies
without accessing the closed connection socket. The same-UID request worker
still enforces the total deadline, size limit and verified TLS. A real local
HTTPS regression covers the current-route and supplied SOCKS transport paths.

Version 0.1.3 retries the two fixed HTTPS GETs at most three times on a transport
reset, EOF or timeout, using new connections within the original total deadline.
Certificate, HTTP-status and response-validation failures are never retried.

Version 0.1.9 also retries temporary DNS resolution failures and transport-
truncated bodies within the same original 20-second total deadline. No timeout
has been increased; a stalled attempt may still consume the entire budget.
Deadline errors name the current fixed phase: DNS, TCP, SOCKS, TLS, request write,
response headers or body. The worker shares only a phase number, never names,
URLs, credentials or response contents. Verified TLS, fixed endpoints, response
limits and the current-route measurement remain unchanged. This diagnostic and
retry hardening does not establish the cause of all public Tor stream failures.
Requires anonymity-runtime 0.1.5 so audited sharing-lock errors are reported
through the supported runtime error boundary rather than a generic exception.

Version 0.1.11 increases the default HTTPS verification deadline from 20 to
40 seconds at the user's request. This covers each normal exit-list or public-IP
verification request, including its transport attempts and complete response.
Separate startup/recovery probes retain their explicit 10-second budgets.
These verification deadlines do not limit ordinary browser downloads or video
playback through Tor. The completed v07 duration test used 0.1.10; this later
change is not a new duration-test result.

Version 0.1.10 uses ordinary Tor circuits with `ConfluxEnabled 0`. This disables
optional circuit bundling, not Tor routing or TLS verification. On the test Pi,
fresh starts with this setting avoided the long transparent-stream stalls seen
with the default `auto` setting. This is a bounded live comparison, not proof of
a general Conflux bug or a guarantee about every exit. The original HTTPS total
deadline and fail-closed routing remain unchanged. The image builder separately
pins the reviewed Tor Project ARM64 package and its archive signing key; the
component archive itself does not add an APT repository to the running Pi.

Version 0.1.5 requires anonymity-runtime 0.1.3 and adds guarded automatic
recovery. Tor's runtime directory survives a daemon restart so the isolated
rotation worker continues to see the current SAFECOOKIE socket.

Version 0.1.6 grants the recovery sandbox CAP_SYS_PTRACE solely for the
existing `ss` ownership verification of the shared DNS process's sockets.
The other sandbox restrictions remain. Three real daemon crashes recovered
automatically in about 17, 25 and 26 seconds on the test Pi, including retries
after failed readiness probes. The Pi and physical controller WLAN paths were
blocked during recovery and reported Tor afterward; local sessions and the
scheduled-rotation worker survived. This is a bounded live acceptance result,
not a promise of recovery time or uninterrupted external TCP connections.

Version 0.1.12 defers an internal recovery tick on the runtime's typed pre-operation lock contention. Public commands and actual operation/probe failures still report errors; no timeout or traffic policy changes.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
