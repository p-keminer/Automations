<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# ALFA AWUS036ACM – optionale Komponente

Version: `0.1.2`, standardmäßig **nicht ausgewählt**. Ziel ist zunächst Kali auf ARM64. Die Datei `component.json` beschreibt die benötigten Pakete und die abzulegende Programmdatei. Sie enthält keine frei ausführbaren Installations-Hooks.

## Was diese Komponente bereitstellt

Die USB-Kennung `0e8d:7612` gehört zu MT7612U-kompatibler Hardware. Der bereits im Linux-Kernel vorhandene Treiber `mt76x2u` bindet passende angeschlossene Geräte automatisch. Seine Firmware-Dateien heißen `mediatek/mt7662.bin` und `mediatek/mt7662_rom_patch.bin`; Kali stellt sie über `firmware-mediatek` bereit. Es wird kein zusätzlicher Fremdtreiber gebaut und kein eigener Erkennungsdienst eingerichtet.

`awus-status` liest ausschließlich die USB- und Netzgeräteinformationen aus `/sys`. Es prüft die tatsächliche Gerätezuordnung, die Treiberbindung und das Vorhandensein einer WLAN-Schnittstelle. Es funktioniert auch nach einem Wechsel des USB-Ports oder mit Namen wie `wlan1`, `wlx…` oder `work0`. Die USB-Kennung kann bei anderen Herstellern ebenfalls vorkommen; sie ist kein Nachweis für die Marke ALFA.

NetworkManager bleibt für die spätere Verbindung des externen Adapters zuständig. Die Komponente benennt keine Schnittstellen um, erzeugt kein WLAN-Profil, lädt keine Module per Befehl nach und ändert weder Routen noch Firewall oder Dienste. `ctrl0` bleibt dem vorhandenen Steuer-WLAN vorbehalten. Ein passender Adapter mit diesem Schnittstellennamen wird als Konflikt gemeldet und nicht als bereit ausgewiesen.

**Nicht Teil dieser Komponente:** Anmeldung an einem Arbeits-WLAN, ausgehende Standardroute, Monitor-Modus oder Umschaltbefehle. Diese Funktionen gehören zu `wifi-control` und `share-control`. Ein Status `ready` bestätigt lediglich Treiberbindung und Schnittstellenerzeugung, keine WLAN-Verbindung und keinen Internetzugang.

## Aufruf

Im vorbereiteten Image:

```bash
awus-status
awus-status --json
```

Direkt aus diesem Repository:

```bash
python3 kali/common/python/awus036acm.py
python3 kali/common/python/awus036acm.py --json
```

Der Aufruf benötigt keine Root-Rechte. `--sysfs-root PFAD` erlaubt das Lesen eines separaten sysfs-Testbaums; Standard ist `/sys`.

| Exitcode | JSON-Status | Bedeutung |
| --- | --- | --- |
| `0` | `ready` | Genau ein passender Adapter, erwarteter Treiber und mindestens eine zugehörige WLAN-Schnittstelle; kein Konflikt mit `ctrl0`. |
| `2` | `missing` | Keine passende USB-Kennung vorhanden. |
| `3` | `not_ready` | Ein passender Adapter ist vorhanden, aber Treiberbindung, Schnittstelle oder Geräteinformationen fehlen; auch ein Konflikt mit `ctrl0` fällt darunter. |
| `4` | `multiple` | Mehrere passende Adapter vorhanden. Alle werden aufgelistet; keiner wird automatisch ausgewählt. |
| `5` | `unavailable` | USB-Geräteliste oder USB-Kennungen nicht vollständig lesbar. |
| `64` | – | Ungültige Kommandozeilenargumente. |

`adapters[].issues` unterscheidet `unbound`, `unexpected_driver`, `no_wireless_interface`, `reserved_control_interface` und `read_error`. Ein Gerät kann mehrere Probleme haben. Während des Ein- oder Aussteckens ist die Ausgabe eine Momentaufnahme; nach Abschluss der Initialisierung erneut prüfen.

## Prüfung ohne Hardware

```bash
python3 -m unittest discover -s kali/common/components/awus036acm/tests -v
```

Die Tests bauen sysfs-Verzeichnisbäume mit echten symbolischen Verknüpfungen auf. Sie prüfen unter anderem andere Adapter, fehlende oder defekte Treiberbindung, wechselnde USB-Ports und Schnittstellennamen, mehrere passende Geräte sowie die Trennung vom Steuer-WLAN. Sie laden keinen Treiber und verändern keine Netzwerke.

## Hardware-Abnahme des ursprünglichen Bausteins

Auf dem geprüften Pi ist `mt76x2u` mit dem passenden USB-Alias und den genannten Firmware-Anforderungen vorhanden. Der AWUS war bei dieser Bestandsaufnahme nicht angeschlossen. Die reale Erkennung und Firmware-Initialisierung waren daher zu diesem Stand noch nicht als bestanden markiert.

Für die Hardware-Abnahme den Adapter anstecken, `awus-status --json` prüfen und kontrollieren, dass das vorhandene Steuer-WLAN und seine Erreichbarkeit unverändert funktionieren. Danach einmal den USB-Port wechseln und erneut prüfen. Ein Verbindungs- oder Routingtest gehört erst zur entsprechenden Erweiterung.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# ALFA AWUS036ACM – optional component

Version: `0.1.2`, **not selected** by default. The initial target is Kali on ARM64.
`component.json` describes the required packages and program file to install.
It contains no freely executable installation hooks.

## What this component provides

USB ID `0e8d:7612` identifies MT7612U-compatible hardware. The Linux kernel's
existing `mt76x2u` driver binds compatible connected devices automatically. Its
firmware files are `mediatek/mt7662.bin` and `mediatek/mt7662_rom_patch.bin`, provided
by Kali's `firmware-mediatek`. No additional third-party driver is built and no
dedicated detection service is installed.

`awus-status` only reads USB and network-device information from `/sys`. It checks
the actual device mapping, driver binding and presence of a wireless interface.
It also works after a USB-port change and with names such as `wlan1`, `wlx…` or
`work0`. Other manufacturers may use the same USB ID; it does not prove the ALFA brand.

NetworkManager remains responsible for subsequent external-adapter connections.
The component does not rename interfaces, create Wi-Fi profiles, load modules by
command, or change routes, firewall rules or services. `ctrl0` remains reserved
for the existing control WLAN. A matching adapter with that interface name is
reported as a conflict, not as ready.

**Outside this component:** connecting to a working WLAN, an outgoing default
route, monitor mode and switching commands. These belong to `wifi-control` and
`share-control`. A `ready` status confirms only driver binding and interface
creation, not a Wi-Fi connection or Internet access.

## Usage

In the prepared image:

```bash
awus-status
awus-status --json
```

Directly from this repository:

```bash
python3 kali/common/python/awus036acm.py
python3 kali/common/python/awus036acm.py --json
```

Root is not required. `--sysfs-root PFAD` allows reading a separate sysfs test
tree; the default is `/sys`.

| Exit code | JSON status | Meaning |
| --- | --- | --- |
| `0` | `ready` | Exactly one matching adapter, expected driver and at least one associated wireless interface; no conflict with `ctrl0`. |
| `2` | `missing` | No matching USB ID present. |
| `3` | `not_ready` | A matching adapter exists, but driver binding, interface or device information is missing; a conflict with `ctrl0` also belongs here. |
| `4` | `multiple` | Multiple matching adapters present. All are listed; none is selected automatically. |
| `5` | `unavailable` | USB device list or USB IDs cannot be read completely. |
| `64` | – | Invalid command-line arguments. |

`adapters[].issues` distinguishes `unbound`, `unexpected_driver`,
`no_wireless_interface`, `reserved_control_interface` and `read_error`. A device
may have several issues. During unplugging or plugging in, the output is a
snapshot; check again after initialization completes.

## Checks without hardware

```bash
python3 -m unittest discover -s kali/common/components/awus036acm/tests -v
```

Tests construct sysfs directory trees with real symbolic links. They cover other
adapters, missing or broken driver binding, changing USB ports and interface
names, multiple matching devices and separation from the control WLAN. They
load no drivers and change no networks.

## Hardware acceptance of the original component

The inspected Pi had `mt76x2u` with the matching USB alias and the stated firmware
requirements. The AWUS was not connected during that inventory. Actual detection
and firmware initialization were therefore not marked as passed at that stage.

For hardware acceptance, connect the adapter, check `awus-status --json` and
verify that the existing control WLAN and its reachability remain unchanged.
Then change the USB port once and check again. Connection or routing tests
belong to the corresponding extension.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
