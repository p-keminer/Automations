# Pi4 case fan control

Optional `auto fan` command for the official Raspberry Pi 4 Case Fan on BCM14.
Requires the separately selected `auto-cli` component and Python libgpiod v2
(`python3-libgpiod`). No forced-on option is exposed.

`--auto` stops/disables the OFF holder and restores the native `gpio-fan`
driver. `--off` enables/starts that holder, which exclusively owns GPIO14 LOW.
Bare invocation and `--status` read actual unit ownership, device-tree limits,
CPU temperature, and the commanded GPIO output. They do not infer fan presence
or actual RPM from the device-tree speed map.

The builder owns boot setup. Only a selected component receives the Pi4 overlay
`dtoverlay=gpio-fan,gpiopin=14,temp=60000,hyst=10000` (or validated selected
thresholds). The trip is resolved through the fan phandle and CPU cooling map,
not a presumed trip index. Bounds are integer Celsius: 20 <= off < on <= 80.
An initially disabled automatic mode enables `automations-fan-off.service` for
boot; it does not start the unit while constructing an image. No separate
persistent settings file is required. Missing overlay/API reports an error.

The requested mode persists as the OFF unit's enabled/disabled state. OFF is
not a hardware cutoff: native AUTO may run before the holder starts, and is
restored by cleanup and ExecStopPost after holder failure or termination.
Systemd restarts are limited to three starts within 60 seconds. CPU thermal
mode and critical trips are never modified. The per-process GPIO lease is
exclusive; no global GPIO reset, thermal-zone disable, or other fan is touched.
Root is required for changes; help is unprivileged. Status requires GPIO-chip
read access (use sudo if denied). Unknown ownership, unit overrides, ambiguous
hardware or thermal mapping are rejected. A runtime-only state sample is valid
only with matching MainPID, GPIO consumer and a monotonic age <= 3 seconds.

A CLI lock serializes changes. Failed/interrupted operations attempt to restore
the prior requested/live modes and explicitly report incomplete rollback.
There are no network operations, old project imports, or web/RPC endpoints.

## Validation

Fixture tests cover DT identity, thermal mapping, ownership, OFF handoff, GPIO
acquisition failure, cleanup, service persistence, fresh/stale status, normal
transitions and rollback including interruption. These are not hardware proof.
GPIO switching and boot acceptance on the new Kali image remain pending.

## Origin

The identity checks and exclusive kernel/libgpiod handoff design were informed
by the user's older `network-sensor` controller fan implementation at commit
`bccabc7c3a5d6a3765775902e04a1cad5a59e4a8`, files
`src/network_sensor/controller_fan.py`, `controller_fan_linux.py`, and
`deployment/images/controller-case-fan.txt`. This component is a new reduced
implementation; no dependency on that repository or its web/RPC layer remains.

Kernel semantics were checked against the Raspberry Pi 6.12 sources:
- https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/hwmon/gpio-fan.c
- https://github.com/raspberrypi/linux/blob/rpi-6.12.y/arch/arm/boot/dts/overlays/gpio-fan-overlay.dts

`pwm1_enable=0` forces full output, and the thermal governor can override manual
`pwm1` writes. These attributes are therefore not used to implement OFF.

## CPU and cooling status

`--status` (and bare `auto fan`) samples the aggregate `/proc/stat` CPU counters
twice with one 0.2-second wait. Output is an aggregate utilization percentage
from the measured interval, not a load average. Idle and iowait are excluded
from busy time; guest time is not counted twice. Missing, decreasing, malformed
or unchanged counters produce `unavailable`, never a guessed zero. Reads are
bounded. CPU temperature comes from the unique `cpu-thermal` sysfs zone; its
mode and existing critical trip are shown when readable. No throttling state
is inferred from temperature or frequency.

CPU information remains visible when the fan overlay or GPIO API is missing.
The fan state then says `unknown (fault)`, a specific diagnostic is printed,
and the command exits nonzero. Available native fan thresholds remain visible
when only the GPIO binding is unavailable. Cooling hints are based on observed
mode and thresholds: explicit OFF above its on threshold, the AUTO hysteresis
band, or reaching the configured critical trip. No rotation or RPM is claimed.

The running test Pi's Python 3.13 cannot use the current Python-3.14-specific
Kali binding package. The Ubuntu WSL v1 package is not a compatible ARM64/Python
replacement. Do not mix these packages or upgrade the live Python environment
for this component. A complete, dependency-consistent new Kali image with
libgpiod Python API v2 is required before switching/boot hardware acceptance.
Installing payloads with the unit disabled permits help/status diagnostics but
does not establish that fan switching is ready.

Counter semantics: https://docs.kernel.org/filesystems/proc.html
