<a id="top"></a>

<div align="center">

[![Deutsch](https://img.shields.io/badge/🇩🇪_Deutsch-24292f?style=for-the-badge)](#deutsch)
[![English](https://img.shields.io/badge/🇬🇧_English-24292f?style=for-the-badge)](#english)

</div>

<a id="deutsch"></a>

# Automations-CLI

Optionaler gemeinsamer Einstieg für separat installierte Befehle. Alle Ausgaben
sind Englisch. `auto --help` listet ausführbare Befehle aus dem festen Verzeichnis
`/usr/local/libexec/automations`; bei der Erkennung wird deren Code nicht ausgeführt.
`auto cert --help` ruft beispielsweise nur den installierten Befehl `cert` auf.
Fehlende Befehle führen zu einer klaren Fehlermeldung, ohne etwas herunterzuladen
oder zu installieren.

Diese Komponente zusammen mit jeder ausgewählten Steuerkomponente installieren.
Das Archivformat beschreibt Nutzdateien, keinen Installer oder eine automatische
Auflösung von Komponentenabhängigkeiten. Der Imagebuilder verlangt diesen Einstieg,
wenn Steuerkomponenten ausgewählt werden. Seine alleinige Installation stellt keine
Netzwerksteuerung bereit.

Der Dispatcher reicht Argumente unverändert weiter, verwendet keine Shell und
erhält die Exitcodes der Module. Er erhöht keine Rechte. Wenn ein Modul Root
benötigt, `sudo auto <command> <action>` verwenden. Vor der Ausführung als Root
weist er Befehle oder übergeordnete Verzeichnisse ab, die für andere Benutzer
beschreibbar sind, nicht Root gehören oder symbolische Links sind. Bei der
Modulausführung setzt er einen festen System-PATH und eine englische Locale,
auch wenn der Interpreter über `/usr/bin/env` ausgewählt wird.

Version 0.1.2 installiert zusätzlich einen festen, Root gehörenden Starter unter
`/usr/bin/auto`. Er reicht Argumente an `/usr/local/bin/auto` weiter, damit
`sudo auto <command> <action>` auch funktioniert, wenn der bestehende sichere
sudo-PATH `/usr/local/bin` ausschließt. Er ändert sudoers nicht, vergibt keine
Rechte und umgeht die normale sudo-Authentifizierung nicht. Der Builder weist
einen vorhandenen Starter, symbolische Links im Ziel und eine Paketzuordnung von
`/usr/bin/auto` oder dessen Pfad vor dem /usr-Merge `/bin/auto` ab.

Die Bash-Vervollständigung listet nur installierte Befehle. Optionen je Befehl
werden aus einfachen Dateien unter
`/usr/local/share/automations/completions/<command>` gelesen; diese enthalten eine
`--option` pro Zeile. Die Vervollständigung führt keine Befehle aus und lädt keine
ausführbaren Hooks. Neue Sitzungen mit bash-completion laden sie automatisch.
Für eine bestehende Bash-Sitzung: `source /etc/bash_completion.d/auto`.

Tests prüfen Argumentweitergabe, Erkennung ohne Ausführung, unbekannte Befehle und
Pfadangaben, unsichere privilegierte Nutzdateien und Vervollständigungsdaten ohne
Shell-Ausführung. Hardwareverhalten gehört zu den Tests der jeweiligen Steuerkomponente.

Die früheren Dispatcher-Tests bestanden. Auf dem Kali-ARM64-Test-Pi mit v05 stimmten
alle acht installierten Kern-/Steuer-Nutzdateien mit ihren Quellprüfsummen überein.
Befehlserkennung, Hilfe, Status ohne Argument, expliziter Status und
Bash-Vervollständigung wurden am 19.10.2026 erfolgreich geprüft. Der Starter aus
0.1.2 ist durch lokale Tests abgedeckt; Live-Installation und der echte Aufruf
`sudo auto` sind ein gesonderter Abnahmeschritt.

<div align="center">

[![Nach oben](https://img.shields.io/badge/⬆_Nach_oben-24292f?style=for-the-badge)](#top)

</div>

---

<a id="english"></a>

# Automations CLI

Optional shared entry point for separately installed commands. All output is
English. `auto --help` lists executable commands from the fixed directory
`/usr/local/libexec/automations`; discovery does not execute their code.
`auto cert --help`, for example, invokes only the installed `cert` command.
Missing commands fail clearly rather than downloading or installing anything.

Install this component together with each selected control component. The
current archive format describes payload files, not an installer or automatic
component dependency resolution. The Imagebuilder requires this entry point
when selecting control components. Installing only this component does not
expose any network controls.

The dispatcher forwards arguments unchanged, uses no shell and retains module
exit codes. It does not elevate permissions. Use `sudo auto <command> <action>`
where the module requires root. Before dispatching as root it rejects commands
or parent directories writable by other users, non-root owners and symlinks.
It supplies a fixed system PATH and English locale when executing a module,
including modules whose interpreter is selected through `/usr/bin/env`.

Version 0.1.2 also installs one fixed, root-owned launcher at `/usr/bin/auto`.
It forwards arguments to `/usr/local/bin/auto`, so `sudo auto <command> <action>`
works when sudo's existing secure PATH excludes `/usr/local/bin`. It does not
change sudoers, grant permissions or bypass normal sudo authentication. The
builder rejects an existing launcher, any symlink in its destination and any
package ownership of `/usr/bin/auto` or its pre-/usr-merge path `/bin/auto`.

Bash completion lists only installed commands. Per-command options are read
from plain files under `/usr/local/share/automations/completions/<command>`;
these contain one `--option` per line. Completion does not run commands or load
executable hooks. New sessions using bash-completion load it automatically.
For an existing Bash session: `source /etc/bash_completion.d/auto`.

Tests exercise argument forwarding, discovery without execution, unknown/path
commands, unsafe privileged payloads and completion data without shell execution.
Hardware-specific behavior belongs to each control component's tests.

The earlier dispatcher tests passed. On the v05 Kali ARM64 test Pi, all eight installed
core/control payloads matched their source checksums. Command discovery, help,
bare status, explicit status and Bash completion were exercised successfully
on 2026-10-19. The 0.1.2 launcher is covered by local tests; live installation
and the real `sudo auto` check are a separate acceptance step.

<div align="center">

[![Back to top](https://img.shields.io/badge/⬆_Back_to_top-24292f?style=for-the-badge)](#top)

</div>
