<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Pi4-Gehäuselüfter steuern

Optionaler Befehl `auto fan` für den offiziellen Raspberry Pi 4 Case Fan an BCM14.
Benötigt die separat ausgewählte Komponente `auto-cli` und Python-libgpiod v2
(`python3-libgpiod`). Eine Option für erzwungenen Dauerbetrieb wird nicht angeboten.

`--auto` stoppt/deaktiviert den OFF-Halter und stellt den nativen Treiber `gpio-fan`
wieder her. `--off` aktiviert/startet diesen Halter, der GPIO14 exklusiv auf LOW hält.
Der Aufruf ohne Argument und `--status` lesen tatsächliche Unit-Zuständigkeit,
Device-Tree-Grenzen, CPU-Temperatur und den angesteuerten GPIO-Ausgang. Aus der
Device-Tree-Drehzahltabelle werden weder ein vorhandener Lüfter noch echte RPM abgeleitet.

Der Builder richtet den Bootzustand ein. Nur bei ausgewählter Komponente wird das
Pi4-Overlay `dtoverlay=gpio-fan,gpiopin=14,temp=60000,hyst=10000` gesetzt, gegebenenfalls
mit anderen validierten Schwellen. Der Schaltpunkt wird über den Lüfter-Phandle und
die CPU-Kühlungszuordnung ermittelt, nicht über einen angenommenen Schaltpunktindex.
Die Grenzen sind ganzzahlige Celsiuswerte: 20 <= off < on <= 80. Ist die Automatik
anfangs ausgeschaltet, wird `automations-fan-off.service` für den Boot aktiviert;
beim Imagebau wird die Unit nicht gestartet. Eine zusätzliche dauerhafte
Einstellungsdatei ist nicht nötig. Fehlendes Overlay oder fehlende API führen zu Fehlern.

Der gewünschte Modus bleibt über den Aktivierungszustand der OFF-Unit erhalten.
OFF ist keine Hardwareabschaltung: Die native Automatik kann vor dem Start des
Halters laufen und wird bei dessen Fehler oder Beendigung durch Bereinigung und
ExecStopPost wiederhergestellt. systemd-Neustarts sind auf drei Starts in 60 Sekunden
begrenzt. CPU-Thermalmodus und kritische Schaltpunkte bleiben unverändert. Die
GPIO-Belegung ist pro Prozess exklusiv; kein globaler GPIO-Reset, kein Abschalten
einer Thermalzone und kein Eingriff in andere Lüfter. Änderungen benötigen Root;
Hilfe ist unprivilegiert. Status benötigt Lesezugriff auf den GPIO-Chip, bei Ablehnung
`sudo` verwenden. Unbekannte Zuständigkeit, Unit-Overrides und mehrdeutige Hardware-
oder Thermalzuordnungen werden abgewiesen. Eine flüchtige Zustandsprobe ist nur mit
passender MainPID, passendem GPIO-Consumer und monotonem Alter <= 3 Sekunden gültig.

Eine CLI-Sperre serialisiert Änderungen. Fehlgeschlagene oder unterbrochene
Operationen versuchen, den vorherigen gewünschten und tatsächlichen Modus
wiederherzustellen, und melden unvollständige Wiederherstellung ausdrücklich.
Es gibt keine Netzwerkoperationen, Importe aus alten Projekten oder Web-/RPC-Endpunkte.

## Prüfung

Fixtures prüfen DT-Identität, Thermalzuordnung, Zuständigkeit, OFF-Übergabe, Fehler
bei der GPIO-Belegung, Bereinigung, Dienstpersistenz, frischen/veralteten Status,
normale Übergänge sowie Wiederherstellung einschließlich Unterbrechung. Das ist kein
Hardwarebeleg. Zum damaligen Stand waren GPIO-Schaltung und Bootabnahme auf dem neuen
Kali-Image noch offen.

## Herkunft

Identitätsprüfungen und die exklusive Übergabe zwischen Kernel und libgpiod wurden
von der älteren Lüfterimplementierung des Benutzers in `network-sensor` angeregt:
Commit `bccabc7c3a5d6a3765775902e04a1cad5a59e4a8`, Dateien
`src/network_sensor/controller_fan.py`, `controller_fan_linux.py` und
`deployment/images/controller-case-fan.txt`. Diese Komponente ist eine neue,
reduzierte Implementierung; sie hängt weder von jenem Repository noch von dessen
Web-/RPC-Schicht ab.

Die Kernelsemantik wurde anhand der Raspberry-Pi-6.12-Quellen geprüft:

- https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/hwmon/gpio-fan.c
- https://github.com/raspberrypi/linux/blob/rpi-6.12.y/arch/arm/boot/dts/overlays/gpio-fan-overlay.dts

`pwm1_enable=0` erzwingt volle Leistung; der Thermal-Governor kann manuelle
Schreibzugriffe auf `pwm1` überschreiben. Diese Attribute werden deshalb nicht für
OFF verwendet.

## CPU- und Kühlungsstatus

`--status` und `auto fan` ohne Argument lesen die gesamten CPU-Zähler aus `/proc/stat`
zweimal mit einer Wartezeit von 0,2 Sekunden. Ausgegeben wird die Gesamtauslastung
des gemessenen Intervalls in Prozent, kein Load Average. Idle und iowait zählen
nicht zur Beschäftigungszeit; Gastzeit wird nicht doppelt gezählt. Fehlende,
rückläufige, fehlerhafte oder unveränderte Zähler ergeben `unavailable`, niemals
eine geschätzte Null. Lesevorgänge sind begrenzt. Die CPU-Temperatur stammt aus der
eindeutigen sysfs-Zone `cpu-thermal`; Modus und vorhandener kritischer Schaltpunkt
werden angezeigt, soweit lesbar. Aus Temperatur oder Frequenz wird kein
Drosselungszustand abgeleitet.

CPU-Daten bleiben auch ohne Lüfter-Overlay oder GPIO-API sichtbar. Der Lüfterzustand
lautet dann `unknown (fault)`, eine konkrete Diagnose wird ausgegeben und der
Exitcode ist ungleich null. Vorhandene native Lüfterschwellen bleiben sichtbar,
wenn lediglich die GPIO-Anbindung fehlt. Kühlungshinweise beruhen auf beobachtetem
Modus und Schwellen: ausdrückliches OFF oberhalb der Einschaltschwelle, das
AUTO-Hystereseband oder der erreichte kritische Schaltpunkt. Rotation und RPM werden
nicht behauptet.

Zum damaligen Stand konnte Python 3.13 des Test-Pi das aktuelle, speziell für
Python 3.14 bestimmte Kali-Binding-Paket nicht verwenden. Das Ubuntu-WSL-v1-Paket
ist kein kompatibler ARM64-/Python-Ersatz. Diese Pakete nicht mischen und die
laufende Python-Umgebung nicht für diese Komponente aktualisieren. Vor der
Hardwareabnahme von Schaltung und Boot ist ein vollständiges neues Kali-Image mit
konsistenten Abhängigkeiten und Python-API v2 von libgpiod nötig. Die Installation
der Nutzdateien bei deaktivierter Unit erlaubt Hilfe-/Statusdiagnosen, belegt aber
keine betriebsbereite Lüfterschaltung.

Zählersemantik: https://docs.kernel.org/filesystems/proc.html

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

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
read access (use `sudo` if denied). Unknown ownership, unit overrides, ambiguous
hardware or thermal mapping are rejected. A runtime-only state sample is valid
only with matching MainPID, GPIO consumer and a monotonic age <= 3 seconds.

A CLI lock serializes changes. Failed/interrupted operations attempt to restore
the prior requested/live modes and explicitly report incomplete rollback.
There are no network operations, old project imports, or web/RPC endpoints.

## Validation

Fixture tests cover DT identity, thermal mapping, ownership, OFF handoff, GPIO
acquisition failure, cleanup, service persistence, fresh/stale status, normal
transitions and rollback including interruption. These are not hardware proof.
At that stage, GPIO switching and boot acceptance on the new Kali image were pending.

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

At that stage, the test Pi's Python 3.13 could not use the current Python-3.14-specific
Kali binding package. The Ubuntu WSL v1 package is not a compatible ARM64/Python
replacement. Do not mix these packages or upgrade the live Python environment
for this component. A complete, dependency-consistent new Kali image with
libgpiod Python API v2 is required before switching/boot hardware acceptance.
Installing payloads with the unit disabled permits help/status diagnostics but
does not establish that fan switching is ready.

Counter semantics: https://docs.kernel.org/filesystems/proc.html

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
