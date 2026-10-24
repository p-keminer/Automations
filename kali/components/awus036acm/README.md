# ALFA AWUS036ACM – optionale Komponente

Version: `0.1.0`, standardmäßig **nicht ausgewählt**. Ziel ist zunächst Kali auf ARM64. Die Datei `component.json` beschreibt die benötigten Pakete und die abzulegende Programmdatei. Sie enthält keine frei ausführbaren Installations-Hooks.

## Was dieser erste Baustein bereitstellt

Die USB-Kennung `0e8d:7612` gehört zu MT7612U-kompatibler Hardware. Der bereits im Linux-Kernel vorhandene Treiber `mt76x2u` bindet passende angeschlossene Geräte automatisch. Seine Firmware-Dateien heißen `mediatek/mt7662.bin` und `mediatek/mt7662_rom_patch.bin`; Kali stellt sie über `firmware-mediatek` bereit. Es wird kein zusätzlicher Fremdtreiber gebaut und kein eigener Erkennungsdienst eingerichtet.

`awus-status` liest ausschließlich die USB- und Netzgeräteinformationen aus `/sys`. Es prüft die tatsächliche Gerätezuordnung, die Treiberbindung und das Vorhandensein einer WLAN-Schnittstelle. Es funktioniert auch nach einem Wechsel des USB-Ports oder mit Namen wie `wlan1`, `wlx…` oder `work0`. Die USB-Kennung kann bei anderen Herstellern ebenfalls vorkommen; sie ist kein Nachweis für die Marke ALFA.

NetworkManager bleibt für die spätere Verbindung des externen Adapters zuständig. Die Komponente benennt keine Schnittstellen um, erzeugt kein WLAN-Profil, lädt keine Module per Befehl nach und ändert weder Routen noch Firewall oder Dienste. `ctrl0` bleibt dem vorhandenen Steuer-WLAN vorbehalten. Ein passender Adapter mit diesem Schnittstellennamen wird als Konflikt gemeldet und nicht als bereit ausgewiesen.

**Noch nicht enthalten:** automatische Anmeldung an einem Arbeits-WLAN, ausgehende Standardroute, Monitor-Modus oder Umschaltbefehle. Diese Funktionen werden getrennt vorbereitet. Ein Status `ready` bestätigt lediglich Treiberbindung und Schnittstellenerzeugung, keine WLAN-Verbindung und keinen Internetzugang.

## Aufruf

Im vorbereiteten Image:

```bash
awus-status
awus-status --json
```

Direkt aus diesem Repository:

```bash
python3 kali/python/awus036acm.py
python3 kali/python/awus036acm.py --json
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
python3 -m unittest discover -s components/awus036acm/tests -v
```

Die Tests bauen sysfs-Verzeichnisbäume mit echten symbolischen Verknüpfungen auf. Sie prüfen unter anderem andere Adapter, fehlende oder defekte Treiberbindung, wechselnde USB-Ports und Schnittstellennamen, mehrere passende Geräte sowie die Trennung vom Steuer-WLAN. Sie laden keinen Treiber und verändern keine Netzwerke.

## Hardware-Abnahme noch offen

Auf dem geprüften Pi ist `mt76x2u` mit dem passenden USB-Alias und den genannten Firmware-Anforderungen vorhanden. Der AWUS war bei dieser Bestandsaufnahme nicht angeschlossen. Die reale Erkennung und Firmware-Initialisierung sind daher noch nicht als bestanden markiert.

Für die spätere Abnahme den Adapter anstecken, `awus-status --json` prüfen und kontrollieren, dass das vorhandene Steuer-WLAN und seine Erreichbarkeit unverändert funktionieren. Danach einmal den USB-Port wechseln und erneut prüfen. Ein Verbindungs- oder Routingtest gehört erst zur entsprechenden Erweiterung.
