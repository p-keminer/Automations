<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Automations

Sammlung eigener Skripte, Helfer und Automatisierungen für wiederkehrende
Aufgaben. Zweck, Voraussetzungen und unterstützte Umgebung werden je Skript
oder Komponente beschrieben.

<div align="center">

[![Struktur](https://img.shields.io/badge/Struktur-24292f?style=for-the-badge)](#de-struktur)
[![Inhalt](https://img.shields.io/badge/Inhalt-24292f?style=for-the-badge)](#de-inhalt)
[![Start](https://img.shields.io/badge/Start-24292f?style=for-the-badge)](#de-start)
[![Nutzung](https://img.shields.io/badge/Nutzung-24292f?style=for-the-badge)](#de-nutzung)
[![Tests](https://img.shields.io/badge/Tests-24292f?style=for-the-badge)](#de-tests)

</div>

<a id="de-struktur"></a>

## Aktuelle Struktur

| Pfad | Vorhandener Inhalt |
|---|---|
| [kali/](kali/) | Bisherige Linux-/Kali-Sammlung mit den folgenden Unterordnern |
| [kali/shell/bash/](kali/shell/bash/) | Bash-Skripte und Bash-Vervollständigung |
| [kali/shell/zsh/](kali/shell/zsh/) | Zsh-Vervollständigung |
| [kali/python/](kali/python/) | Python-Skripte, Runtime und TXT-Hilfen |
| [kali/components/](kali/components/) | Paketmanifeste, Komponenten-Anleitungen und Tests |
| [kali/tools/](kali/tools/) | Werkzeuge für Katalogprüfung und Paketbau |
| [kali/tests/](kali/tests/) | Tests des gemeinsamen Komponentenwerkzeugs |
| [.github/](.github/) | Automatische Prüfungen |

Für neue Automatisierungen gehören Zweck, unterstützte Umgebung,
Voraussetzungen und verständliche Beispielaufrufe zur jeweiligen Anleitung.
Passende Tests und eine klare Beschreibung möglicher Änderungen erleichtern
die Weiterentwicklung.

<a id="de-inhalt"></a>

## Aktueller Inhalt

Die bisherige Sammlung umfasst elf Komponenten mit Schwerpunkt Linux,
Netzwerk und Raspberry Pi.

| Bereich | Vorhandene Komponenten |
|---|---|
| Gemeinsamer CLI-Einstieg | [auto-cli](kali/components/auto-cli/README.md) mit separater Vervollständigung für [Bash](kali/shell/bash/auto-completion.sh) und [Zsh](kali/shell/zsh/_auto) |
| WLAN und Netzwerk | [wifi-control](kali/components/wifi-control/README.md), [share-control](kali/components/share-control/README.md), [ap-control](kali/components/ap-control/README.md), [hotspot-control](kali/components/hotspot-control/README.md) |
| Zugriff und Zertifikate | [ssh-control](kali/components/ssh-control/README.md), [cert-control](kali/components/cert-control/README.md) |
| Tor und Routing | [tor-control](kali/components/tor-control/README.md), [anonymity-runtime](kali/components/anonymity-runtime/README.md) |
| Hardware | [awus036acm](kali/components/awus036acm/README.md), [fan-control](kali/components/fan-control/README.md) |

Die Detailanleitungen enthalten Voraussetzungen, Befehle und Grenzen.
Die vorhandenen Netzwerkmodule erwarten die dafür eingerichtete
Kali-/Pi4-Umgebung.

<a id="de-start"></a>

## Start und Paketbau

Im ausgecheckten Repository lassen sich die vorhandenen Komponenten unter
Linux oder WSL mit Python 3.12+ und Git prüfen und paketieren. Bash wird für
entsprechende Skripte benötigt. Die folgenden Aufrufe beginnen im
Repository-Hauptverzeichnis und wechseln in die Kali-Sammlung:

```bash
cd kali
python3 tools/components.py list --json
python3 -m unittest discover -s tests -v
python3 tools/components.py check --component wifi-control
python3 tools/components.py build --component wifi-control --output dist
```

`check` prüft Quellen und Komponententests. `build` erzeugt ein Quellarchiv,
eine SHA-256-Datei und einen JSON-Baubeleg unter `kali/dist/`.

Dieses Paketwerkzeug gehört zur bestehenden Linux-/Kali-Sammlung.
Andere Skriptarten benötigen ihre eigenen passenden Start- und Prüfwege.

<a id="de-nutzung"></a>

## Nutzung

Zuerst die Anleitung des gewünschten Skripts lesen. Dort stehen benötigte
Programme, Rechte, Parameter und die Wirkung auf Dateien, Dienste oder Netzwerke.

Die installierten Linux-Komponenten bieten beispielsweise:

```bash
auto --help
auto wifi --help
auto wifi --status
auto fan --status
```

`auto` zeigt nur tatsächlich installierte Unterbefehle.
CLI-Ausgaben sind Englisch; Komponentenhilfen liegen als
deutsche und englische TXT-Dateien vor. Einzelne Schaltbefehle und geschützte
Statusabfragen benötigen `sudo`. Ausführliche Betriebsbeispiele stehen in den
oben verlinkten Komponenten-READMEs.


<a id="de-tests"></a>

## Tests und CI

Der vorhandene [GitHub-Workflow](.github/workflows/components.yml) prüft den
Komponentenkatalog, führt Tests aus und vergleicht drei unabhängige Paketbauten.
Für Routing und Gast-AP gibt es zusätzliche Prüfungen in isolierten Linux-
Netzwerk-Namespaces. Paketartefakte werden 14 Tage aufbewahrt.

Eine optionale Vertragsprüfung mit dem Imagebuilder benötigt einen festen
Commit-SHA in `BUILDER_REF`. Ohne ihn bleiben diese Integrationsgruppen
ausgelassen. Für neue Skriptarten werden Prüfungen passend zu deren Umgebung
ergänzt. CI-Erfolg ersetzt keinen erforderlichen Geräte- oder Praxistest.



<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Automations

A collection of my own scripts, helpers and automations for recurring tasks.
Each script or component documents its purpose, requirements and supported
environment.

<div align="center">

[![Structure](https://img.shields.io/badge/Structure-24292f?style=for-the-badge)](#en-structure)
[![Contents](https://img.shields.io/badge/Contents-24292f?style=for-the-badge)](#en-contents)
[![Start](https://img.shields.io/badge/Start-24292f?style=for-the-badge)](#en-start)
[![Usage](https://img.shields.io/badge/Usage-24292f?style=for-the-badge)](#en-usage)
[![Tests](https://img.shields.io/badge/Tests-24292f?style=for-the-badge)](#en-tests)

</div>

<a id="en-structure"></a>

## Current structure

| Path | Existing contents |
|---|---|
| [kali/](kali/) | Existing Linux/Kali collection with the subdirectories below |
| [kali/shell/bash/](kali/shell/bash/) | Bash scripts and Bash completion |
| [kali/shell/zsh/](kali/shell/zsh/) | Zsh completion |
| [kali/python/](kali/python/) | Python scripts, runtime and TXT help |
| [kali/components/](kali/components/) | Package manifests, component instructions and tests |
| [kali/tools/](kali/tools/) | Catalog validation and packaging tools |
| [kali/tests/](kali/tests/) | Tests for the shared component tooling |
| [.github/](.github/) | Automated checks |

Each new automation should document its purpose, supported environment,
requirements and understandable example commands. Appropriate tests and
clear descriptions of possible changes support further development.


<a id="en-contents"></a>

## Current contents

The existing collection comprises eleven components focused on Linux,
networking and Raspberry Pi.

| Area | Existing components |
|---|---|
| Shared CLI entry point | [auto-cli](kali/components/auto-cli/README.md) with separate completion for [Bash](kali/shell/bash/auto-completion.sh) and [Zsh](kali/shell/zsh/_auto) |
| Wi-Fi and networking | [wifi-control](kali/components/wifi-control/README.md), [share-control](kali/components/share-control/README.md), [ap-control](kali/components/ap-control/README.md), [hotspot-control](kali/components/hotspot-control/README.md) |
| Access and certificates | [ssh-control](kali/components/ssh-control/README.md), [cert-control](kali/components/cert-control/README.md) |
| Tor and routing | [tor-control](kali/components/tor-control/README.md), [anonymity-runtime](kali/components/anonymity-runtime/README.md) |
| Hardware | [awus036acm](kali/components/awus036acm/README.md), [fan-control](kali/components/fan-control/README.md) |

The detailed instructions describe requirements, commands and limitations.
The existing network modules expect the Kali/Pi4 environment configured
for them.

<a id="en-start"></a>

## Getting started and packaging

From the checked-out repository, existing components can be checked and
packaged on Linux or WSL with Python 3.12+ and Git. Bash is required for the
relevant scripts. The following commands start in the repository root
and switch to the Kali collection:

```bash
cd kali
python3 tools/components.py list --json
python3 -m unittest discover -s tests -v
python3 tools/components.py check --component wifi-control
python3 tools/components.py build --component wifi-control --output dist
```

`check` validates sources and runs component tests. `build` creates a source
archive, SHA-256 file and JSON build record in `kali/dist/`.

This packaging tool belongs to the existing Linux/Kali collection. Other
types of scripts need their own appropriate execution and validation paths.

<a id="en-usage"></a>

## Usage

Read the chosen script's instructions first. They describe required programs,
permissions, parameters and effects on files, services or networks.

For example, installed Linux components provide:

```bash
auto --help
auto wifi --help
auto wifi --status
auto fan --status
```

`auto` lists only subcommands that are actually installed.
CLI output is English; component references are provided as German and English
TXT files. Some switching commands and protected status queries require `sudo`.
Detailed operating examples are in the component READMEs linked above.

<a id="en-tests"></a>

## Tests and CI

The existing [GitHub workflow](.github/workflows/components.yml) validates the
component catalog, runs tests and compares three independent package builds.
Routing and guest-AP checks also use isolated Linux network namespaces.
Package artifacts are retained for 14 days.

Optional image-builder contract checks require a pinned commit SHA in
`BUILDER_REF`. Without it, those integration groups are skipped. Tests for new
types of scripts are added according to their environment. Passing CI does
not replace necessary device or practical testing.


<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
