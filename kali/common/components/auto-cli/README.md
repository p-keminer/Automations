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
