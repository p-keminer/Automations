import contextlib
import copy
from dataclasses import dataclass
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("host_ssh_module", ROOT / "portable/python/host_ssh.py")
ssh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ssh)


@dataclass(frozen=True)
class Profile:
    platform: str = "kali-host"
    configured: bool = True
    protected_interfaces: tuple = ()
    ssh_service: str = "ssh.service"
    identity: str = "fixture"


def hook(*commands):
    return " ; ".join("{ path=" + command[0] + " ; argv[]=" + " ".join(command)
                      + " ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
                      for command in commands)


class FakeRunner:
    """No call from these tests reaches systemctl, sshd, ss or a real service."""
    def __init__(self, root):
        self.root, self.calls, self.failures = root, [], {}
        self.unit = {name: "" for name in ssh.PROPERTIES}
        self.unit.update(Id="ssh.service", LoadState="loaded", ActiveState="inactive", SubState="dead",
                         UnitFileState="disabled", MainPID="0", FragmentPath="/usr/lib/systemd/system/ssh.service",
                         NeedDaemonReload="no", Type="notify", KillMode="process", DynamicUser="no", PrivateNetwork="no",
                         ExecStart=hook((ssh.SSHD, "-D", "$SSHD_OPTS")),
                         ExecStartPre=hook((ssh.SSHD, "-t")),
                         ExecReload=hook((ssh.SSHD, "-t"), ("/bin/kill", "-HUP", "$MAINPID")),
                         EnvironmentFiles="/etc/default/ssh (ignore_errors=yes)")
        self.sockets = {name: dict(LoadState="not-found", ActiveState="inactive", UnitFileState="")
                        for name in ("ssh.socket", "sshd.socket")}
        self.config = "port 22\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\n"
        self.extra_listeners = []
        self.missing_listener = False
        self.start_stalls = False
        self.readback_hook = None
        self.property_lines = {}
        self.config_invalid = False
        self.full_check_failure = False
        self.start_pre_checks = 0
        for path in (ssh.SYSTEMCTL, ssh.SSHD, ssh.SS, "/bin/kill", "/usr/bin/mkdir"):
            self.file(path, "fixture executable", 0o755)
        self.file(ssh.CONFIG, "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        self.file("/etc/default/ssh", '# Defaults\nSSHD_OPTS=""\n')
        self.file("/usr/lib/systemd/system/ssh.service", "fixture unit\n")
        for path in ("run/systemd/system", "etc/ssh/sshd_config.d", "proc/123"):
            (root / path).mkdir(parents=True, exist_ok=True)
        (root / "proc/123/exe").symlink_to(ssh.SSHD)
        self.file("/proc/123/status", "Name:\tsshd\nUid:\t0\t0\t0\t0\n")
        self.file("/proc/123/cgroup", "0::/system.slice/ssh.service\n")

    def file(self, path, text, mode=0o644):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        target.chmod(mode)
        return target

    def activate(self, active=True):
        runtime = self.root / "run/sshd"
        if active:
            runtime.mkdir(exist_ok=True)
        elif runtime.exists():
            runtime.rmdir()
        self.unit.update(ActiveState="active" if active else "inactive", SubState="running" if active else "dead",
                         MainPID="123" if active else "0", ControlGroup="/system.slice/ssh.service" if active else "")

    def __call__(self, args):
        self.calls.append(args)
        action = args[1] if args[0] == ssh.SYSTEMCTL else None
        failure = self.failures.get(action or args[0])
        if failure:
            if callable(failure):
                failure()
            else:
                self.failures.pop(action or args[0])
                return subprocess.CompletedProcess(args, 1, "", "fixture failure")
        output = ""
        if args[:2] == [ssh.SYSTEMCTL, "show"]:
            unit = self.sockets.get(args[2], self.unit)
            if self.readback_hook:
                self.readback_hook()
            keys = args[3].removeprefix("--property=").split(",")
            output = "\n".join(key + "=" + value for key in keys
                               for value in self.property_lines.get(key, (unit.get(key, ""),)))
        elif action in ("enable", "disable"):
            self.unit["UnitFileState"] = "enabled" if action == "enable" else "disabled"
        elif action in ("start", "stop"):
            if action == "start" and self.start_stalls:
                pass
            elif action == "start":
                # Model systemd RuntimeDirectory creation before ExecStartPre=-t.
                (self.root / "run/sshd").mkdir(exist_ok=True)
                self.start_pre_checks += 1
                if self.config_invalid or self.full_check_failure:
                    self.activate(False)
                    self.unit.update(ActiveState="failed", SubState="failed")
                    return subprocess.CompletedProcess(args, 1, "", "fixture pre-start validation failure")
                self.activate()
            else:
                self.activate(False)
        elif args in ([ssh.SSHD, flag, "-f", ssh.CONFIG] for flag in ("-t", "-T", "-G")):
            if self.config_invalid:
                return subprocess.CompletedProcess(args, 255, "", "fixture native configuration syntax failure")
            if args[1] != "-G" and (self.full_check_failure or not (self.root / "run/sshd").is_dir()):
                return subprocess.CompletedProcess(args, 255, "", "fixture full validation failure")
            output = self.config if args[1] in ("-T", "-G") else ""
        elif args[:3] == [ssh.SS, "-H", "-ltnp"]:
            family = args[-1]
            rows = []
            if self.unit["ActiveState"] == "active" and not self.missing_listener:
                address = "0.0.0.0:22" if family == "-4" else "[::]:22"
                rows.append(f'LISTEN 0 128 {address} *:* users:(("sshd",pid=123,fd=3))')
            rows.extend(row for row_family, row in self.extra_listeners if row_family == family)
            output = "\n".join(rows)
        else:
            raise AssertionError("Unexpected command: " + repr(args))
        return subprocess.CompletedProcess(args, 0, output, "")

    def actions(self):
        return [args[1] for args in self.calls if args[0] == ssh.SYSTEMCTL and args[1] != "show"]


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system = FakeRunner(self.root)
        self.backend = ssh.HostSSH(Profile(), root=self.root, runner=self.system,
                                   owner_uid=os.geteuid(), sleeper=lambda _: None)
        self.root_patch = patch.object(ssh.os, "geteuid", return_value=0)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def change(self, enabled):
        return self.backend.change(enabled)

    def assert_unchanged(self):
        self.assertEqual(self.system.actions(), [])
        self.assertEqual(self.system.unit["ActiveState"], "inactive")
        self.assertEqual(self.system.unit["UnitFileState"], "disabled")

    def test_inactive_status_has_configured_ports_and_no_claim_of_reachability(self):
        state = self.backend.inspect()
        self.assertTrue(state["available"])
        self.assertEqual(state["ports"], [22])
        self.assertEqual(state["listeners"], [])
        self.assertEqual(state["firewall_reachability"], "not assessed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ssh.print_status(state)
        self.assertIn("not assessed", output.getvalue())
        self.assertIn("Boot enablement: disabled", output.getvalue())
        self.assert_unchanged()

    def test_on_and_off_roundtrip_changes_only_selected_service(self):
        state, changed = self.change(True)
        self.assertTrue(changed)
        self.assertEqual(state["active_state"], "active")
        self.assertEqual(state["listeners"], [("0.0.0.0", 22), ("::", 22)])
        state, changed = self.change(False)
        self.assertTrue(changed)
        self.assertEqual(state["active_state"], "inactive")
        self.assertEqual(self.system.actions(), ["enable", "start", "stop", "disable"])
        self.assertTrue(all(args[-1] == "ssh.service" for args in self.system.calls
                            if args[0] == ssh.SYSTEMCTL and args[1] != "show"))

    def test_inactive_status_parses_configuration_without_creating_runtime_directory(self):
        self.assertFalse((self.root / "run/sshd").exists())
        state = self.backend.inspect()
        self.assertTrue(state["available"])
        self.assertEqual(state["ports"], [22])
        self.assertEqual([args[1] for args in self.system.calls if args[0] == ssh.SSHD], ["-G"])
        self.assertFalse((self.root / "run/sshd").exists())
        self.assert_unchanged()

    def test_off_readback_survives_runtime_directory_removal_without_restarting(self):
        self.system.activate()
        self.system.unit["UnitFileState"] = "enabled"
        state, changed = self.change(False)
        self.assertTrue(changed)
        self.assertEqual(state["active_state"], "inactive")
        self.assertEqual(state["unit_file_state"], "disabled")
        self.assertFalse((self.root / "run/sshd").exists())
        self.assertEqual(self.system.actions(), ["stop", "disable"])
        self.assertEqual([args[1] for args in self.system.calls if args[0] == ssh.SSHD],
                         ["-t", "-T", "-G"])

    def test_activation_uses_mandatory_pre_start_test_then_full_active_readback(self):
        self.assertFalse((self.root / "run/sshd").exists())
        self.assertTrue(self.change(True)[0]["available"])
        self.assertEqual(self.system.start_pre_checks, 1)
        self.assertTrue((self.root / "run/sshd").is_dir())
        flags = [args[1] for args in self.system.calls if args[0] == ssh.SSHD]
        self.assertEqual(flags, ["-G", "-t", "-T"])
        started = self.system.calls.index([ssh.SYSTEMCTL, "start", "ssh.service"])
        for args in ([ssh.SSHD, "-t", "-f", ssh.CONFIG], [ssh.SSHD, "-T", "-f", ssh.CONFIG]):
            self.assertGreater(self.system.calls.index(args), started)

    def test_native_inactive_syntax_failure_prevents_service_actions(self):
        self.system.config_invalid = True
        with self.assertRaisesRegex(ssh.Error, r"sshd failed \(exit 255\)"):
            self.change(True)
        self.assertEqual([args[1] for args in self.system.calls if args[0] == ssh.SSHD], ["-G"])
        self.assertFalse((self.root / "run/sshd").exists())
        self.assert_unchanged()

    def test_active_validation_failure_never_falls_back_to_parse_only(self):
        self.system.activate()
        self.system.full_check_failure = True
        with self.assertRaisesRegex(ssh.Error, r"sshd failed \(exit 255\)"):
            self.change(False)
        self.assertEqual([args[1] for args in self.system.calls if args[0] == ssh.SSHD], ["-t"])
        self.assertEqual(self.system.actions(), [])
        self.assertEqual(self.system.unit["ActiveState"], "active")

    def test_pre_start_full_validation_failure_restores_previous_off_state(self):
        self.system.full_check_failure = True
        with self.assertRaisesRegex(ssh.Error, "previous active/enabled state restored"):
            self.change(True)
        self.assertEqual(self.system.start_pre_checks, 1)
        self.assertEqual(self.system.actions(), ["enable", "start", "stop", "disable"])
        self.assertEqual(self.system.unit["ActiveState"], "inactive")
        self.assertEqual(self.system.unit["UnitFileState"], "disabled")
        self.assertFalse((self.root / "run/sshd").exists())

    def test_idempotence_and_mixed_previous_states(self):
        self.assertFalse(self.change(False)[1])
        self.system.activate()
        state, changed = self.change(True)
        self.assertTrue(changed)
        self.assertEqual(self.system.actions(), ["enable"])
        self.assertFalse(self.change(True)[1])

    def test_service_alias_uses_only_explicit_profile_name(self):
        self.backend.profile = Profile(ssh_service="sshd.service")
        self.backend.service = "sshd.service"
        self.change(True)
        self.assertTrue(all(args[-1] == "sshd.service" for args in self.system.calls
                            if args[0] == ssh.SYSTEMCTL and args[1] != "show"))

    def test_known_mkdir_pre_start_hook_supported(self):
        self.system.unit["ExecStartPre"] = hook(("/usr/bin/mkdir", "-p", "/run/sshd"), (ssh.SSHD, "-t"))
        self.assertTrue(self.change(True)[0]["available"])

    def test_two_reload_property_lines_accept_the_standard_ordered_commands(self):
        self.system.property_lines["ExecReload"] = (
            hook((ssh.SSHD, "-t")), hook(("/bin/kill", "-HUP", "$MAINPID")))
        state, changed = self.change(True)
        self.assertTrue(changed)
        self.assertTrue(state["available"])
        self.assertEqual(self.backend.executable_hooks(state["unit"]["ExecReload"]),
                         [(ssh.SSHD, "-t"), ("/bin/kill", "-HUP", "$MAINPID")])
        self.assertEqual(self.system.actions(), ["enable", "start"])

    def test_two_pre_start_property_lines_preserve_the_supported_command_order(self):
        commands = (("/usr/bin/mkdir", "-p", "/run/sshd"), (ssh.SSHD, "-t"))
        self.system.property_lines["ExecStartPre"] = tuple(hook(command) for command in commands)
        state = self.backend.inspect()
        self.assertEqual(self.backend.executable_hooks(state["unit"]["ExecStartPre"]),
                         list(commands))
        self.assert_unchanged()

    def test_repeated_reload_lines_cannot_hide_reordered_or_extra_hooks(self):
        standard = (hook((ssh.SSHD, "-t")), hook(("/bin/kill", "-HUP", "$MAINPID")))
        for lines in (standard[::-1], standard + (hook((ssh.SSHD, "-t")),),
                      standard + (hook(("/tmp/foreign-hook",)),)):
            with self.subTest(lines=lines), self.assertRaisesRegex(ssh.Error, "reload hooks"):
                self.system.property_lines["ExecReload"] = lines
                self.change(True)
        self.assert_unchanged()

    def test_other_duplicate_properties_are_rejected_even_when_values_match(self):
        for key in ("Id", "ExecStart", "UnknownProperty", "ExecStop", "Environment"):
            with self.subTest(key=key), self.assertRaisesRegex(ssh.Error, "Duplicate"):
                ssh.fields(key + "=same\n" + key + "=same\n")
        for key in ("Id", "ExecStart"):
            with self.subTest(key=key), self.assertRaisesRegex(ssh.Error, "Duplicate"):
                value = self.system.unit[key]
                self.system.property_lines = {key: (value, value)}
                self.change(True)
        self.assert_unchanged()

    def test_root_and_explicit_profile_are_required_before_actions(self):
        with patch.object(ssh.os, "geteuid", return_value=1000), self.assertRaisesRegex(ssh.Error, "Root"):
            self.change(True)
        self.backend.profile = Profile(configured=False)
        with self.assertRaisesRegex(ssh.Error, "explicit"):
            self.change(True)
        self.assert_unchanged()

    def test_unknown_service_or_platform_rejected(self):
        for profile in (Profile(platform="pi4"), Profile(ssh_service="arbitrary.service")):
            with self.assertRaises(ssh.Error):
                ssh.HostSSH(profile)

    def test_missing_systemd_or_service_is_unavailable_not_successful_off(self):
        self.system.unit["LoadState"] = "not-found"
        state = self.backend.inspect()
        self.assertFalse(state["available"])
        self.assertIn("not installed", state["reason"])
        with self.assertRaisesRegex(ssh.Error, "unavailable"):
            self.change(False)
        (self.root / "run/systemd/system").rmdir()
        self.assertIn("systemd is not running", self.backend.inspect()["reason"])
        self.assert_unchanged()

    def test_command_failure_is_not_absent_hardware(self):
        self.system.failures["show"] = lambda: (_ for _ in ()).throw(ssh.Error("manager failure"))
        with self.assertRaisesRegex(ssh.Error, "manager failure"):
            self.backend.inspect()

    def test_unknown_hooks_dropins_environment_or_namespace_rejected(self):
        originals = dict(self.system.unit)
        cases = dict(ExecStart=hook(("/bin/sh", "-c", "anything")), ExecStartPre=hook(("/tmp/hook",)),
                     ExecStartPost=hook(("/tmp/hook",)), ExecStop=hook(("/tmp/hook",)),
                     ExecStopPost=hook(("/tmp/hook",)), ExecCondition=hook(("/tmp/hook",)),
                     ExecReload=hook(("/tmp/hook",)), DropInPaths="/etc/systemd/system/ssh.service.d/custom.conf",
                     Environment="SSHD_OPTS=-p2222", PassEnvironment="SSHD_OPTS", EnvironmentFiles="/tmp/environment (ignore_errors=yes)",
                     PrivateNetwork="yes", NetworkNamespacePath="/run/netns/foreign", User="other",
                     NeedDaemonReload="yes", Job="23 /org/freedesktop/systemd1/job/23")
        for name, value in cases.items():
            with self.subTest(name=name), self.assertRaises(ssh.Error):
                self.system.unit = dict(originals, **{name: value})
                self.change(True)
        self.system.unit = originals
        self.assert_unchanged()

    def test_root_owned_usr_merge_symlinks_are_supported(self):
        target = self.root / "usr/bin/kill"
        target.write_text("fixture executable")
        target.chmod(0o755)
        (self.root / "bin/kill").unlink()
        (self.root / "bin").rmdir()
        (self.root / "bin").symlink_to("usr/bin", target_is_directory=True)
        self.assertTrue(self.change(True)[0]["available"])

    def test_nonempty_environment_file_rejected(self):
        self.system.file("/etc/default/ssh", 'SSHD_OPTS="-f /tmp/untrusted"\n')
        with self.assertRaisesRegex(ssh.Error, "SSHD_OPTS"):
            self.change(True)
        self.assert_unchanged()

    def test_socket_activation_is_never_disabled_implicitly(self):
        self.system.sockets["ssh.socket"] = dict(LoadState="loaded", ActiveState="active", UnitFileState="enabled")
        with self.assertRaisesRegex(ssh.Error, "socket activation"):
            self.change(True)
        self.assert_unchanged()

    def test_unsafe_configuration_and_include_rejected_before_validation_command(self):
        self.system.file("/etc/ssh/sshd_config.d/unsafe.conf", "Port 2222\n", 0o666)
        with self.assertRaisesRegex(ssh.Error, "trusted owner"):
            self.change(True)
        self.assertFalse(any(args[0] == ssh.SSHD for args in self.system.calls))
        self.assert_unchanged()

    def test_include_escape_and_cycle_rejected(self):
        for content in ("Include /tmp/*.conf\n", "Include /etc/ssh/sshd_config\n"):
            self.system.file(ssh.CONFIG, content)
            self.backend.pins = {}
            with self.assertRaises(ssh.Error):
                self.change(True)
        self.assert_unchanged()

    def test_failed_config_check_prevents_actions(self):
        self.system.failures[ssh.SSHD] = True
        with self.assertRaisesRegex(ssh.Error, "sshd failed"):
            self.change(True)
        self.assert_unchanged()

    def test_foreign_daemon_on_other_port_is_not_taken_over(self):
        self.system.extra_listeners = [("-4", 'LISTEN 0 128 127.0.0.1:2222 *:* users:(("sshd",pid=777,fd=3))')]
        with self.assertRaisesRegex(ssh.Error, "foreign SSH"):
            self.change(True)
        self.assert_unchanged()

    def test_other_service_on_configured_port_is_not_killed(self):
        self.system.extra_listeners = [("-4", 'LISTEN 0 128 0.0.0.0:22 *:* users:(("other",pid=777,fd=3))')]
        with self.assertRaisesRegex(ssh.Error, "unrelated service"):
            self.change(True)
        self.assert_unchanged()

    def test_unrelated_service_on_other_port_is_left_alone(self):
        self.system.extra_listeners = [("-4", 'LISTEN 0 128 0.0.0.0:443 *:* users:(("other",pid=777,fd=3))')]
        self.assertTrue(self.change(True)[0]["available"])

    def test_missing_process_visibility_is_not_treated_as_safe(self):
        self.system.extra_listeners = [("-4", "LISTEN 0 128 0.0.0.0:22 *:*")]
        with self.assertRaisesRegex(ssh.Error, "ownership"):
            self.change(True)
        self.assert_unchanged()

    def test_wrong_main_process_cgroup_rejected(self):
        self.system.activate()
        self.system.file("/proc/123/cgroup", "0::/user.slice/other\n")
        with self.assertRaisesRegex(ssh.Error, "selected systemd service"):
            self.change(False)
        self.assertEqual(self.system.actions(), [])

    def test_enable_then_failed_start_restores_both_previous_states(self):
        self.system.failures["start"] = True
        with self.assertRaisesRegex(ssh.Error, "previous active/enabled state restored"):
            self.change(True)
        self.assertEqual(self.system.unit["ActiveState"], "inactive")
        self.assertEqual(self.system.unit["UnitFileState"], "disabled")
        self.assertEqual(self.system.actions(), ["enable", "start", "stop", "disable"])

    def test_failed_disable_restores_active_enabled_service(self):
        self.system.activate()
        self.system.unit["UnitFileState"] = "enabled"
        self.system.failures["disable"] = True
        with self.assertRaisesRegex(ssh.Error, "previous active/enabled state restored"):
            self.change(False)
        self.assertEqual(self.system.unit["ActiveState"], "active")
        self.assertEqual(self.system.unit["UnitFileState"], "enabled")

    def test_failed_start_preserves_previously_enabled_but_inactive(self):
        self.system.unit["UnitFileState"] = "enabled"
        self.system.failures["start"] = True
        with self.assertRaisesRegex(ssh.Error, "previous active/enabled state restored"):
            self.change(True)
        self.assertEqual(self.system.unit["ActiveState"], "inactive")
        self.assertEqual(self.system.unit["UnitFileState"], "enabled")

    def test_bounded_wait_rolls_back(self):
        self.system.start_stalls = True
        with self.assertRaisesRegex(ssh.Error, "bounded wait"):
            self.change(True)
        self.assertLess(len(self.system.calls), 80)
        self.assertEqual(self.system.unit["UnitFileState"], "disabled")

    def test_listener_readback_failure_rolls_back(self):
        self.system.missing_listener = True
        with self.assertRaisesRegex(ssh.Error, "previous active/enabled state restored.*listeners"):
            self.change(True)
        self.assertEqual(self.system.unit["ActiveState"], "inactive")

    def test_rollback_failure_is_explicit_and_does_not_kill_processes(self):
        self.system.failures["start"] = True
        self.system.failures["disable"] = True
        with self.assertRaisesRegex(ssh.Error, "rollback incomplete"):
            self.change(True)
        self.assertTrue(all(args[0] in (ssh.SYSTEMCTL, ssh.SSHD, ssh.SS) for args in self.system.calls))

    def test_external_config_edit_stops_rollback_actions(self):
        def edit_then_fail():
            self.system.file(ssh.CONFIG, "Port 2222\n")
            raise ssh.Error("changed externally")
        self.system.failures["start"] = edit_then_fail
        with self.assertRaisesRegex(ssh.Error, "rollback incomplete.*configuration changed"):
            self.change(True)
        self.assertEqual(self.system.actions(), ["enable", "start"])
        self.assertEqual((self.root / ssh.CONFIG.lstrip("/")).read_text(), "Port 2222\n")

    def test_fixed_lock_serializes_and_rejects_symlink(self):
        with self.backend.lock():
            with self.assertRaisesRegex(ssh.Error, "Another host SSH"):
                with self.backend.lock():
                    pass
        (self.root / ssh.LOCK.lstrip("/")).unlink()
        (self.root / ssh.LOCK.lstrip("/")).symlink_to(self.root / ssh.CONFIG.lstrip("/"))
        with self.assertRaises(OSError):
            with self.backend.lock():
                pass

    def test_cli_help_without_profile_or_root_and_exclusive_actions(self):
        with patch.object(ssh, "load_profile", side_effect=AssertionError("must not load")), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
            ssh.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            ssh.main(["--on", "--off"])
        self.assertEqual(result.exception.code, 2)

    def test_cli_status_and_missing_service_exit_code(self):
        output = io.StringIO()
        with patch.object(ssh, "HostSSH", return_value=self.backend), contextlib.redirect_stdout(output):
            self.assertEqual(ssh.main([], profile=Profile()), 0)
            self.system.unit["LoadState"] = "not-found"
            self.assertEqual(ssh.main(["--status"], profile=Profile()), 3)
        self.assert_unchanged()

    def test_real_runner_has_fixed_environment_timeout_and_no_shell(self):
        with patch.object(ssh.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as called:
            ssh.run([ssh.SYSTEMCTL, "show", "ssh.service"])
        arguments = called.call_args.kwargs
        self.assertEqual(arguments["timeout"], 15)
        self.assertEqual(arguments["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", arguments)
        self.assertEqual(set(arguments["env"]), {"PATH", "LC_ALL"})


if __name__ == "__main__":
    unittest.main()
