# Selected-uplink Internet sharing

Optional `share-control` **0.1.12**, installed with `auto-cli`. Installation does
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
python3 -B tools/components.py check --component share-control
sudo unshare -n python3 components/share-control/tests/native_watch_check.py
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
sudo unshare -n python3 components/share-control/tests/namespace_check.py
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
@lo or changing bind mode separately was insufficient. The combined mode
refreshes that index without a resolver restart on DNS metadata updates.
The existing control/loopback listen selection and privacy guard are retained.
Native backend fixtures do not replace real Tor/iPhone acceptance.
