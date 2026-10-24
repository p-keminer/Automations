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
