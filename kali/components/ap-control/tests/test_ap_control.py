"""Offline AP tests. No real service/network command is executed."""
from contextlib import redirect_stdout, redirect_stderr
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "python/auto_ap.py"
SPEC = importlib.util.spec_from_file_location("auto_ap", SOURCE)
ap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ap)
CONFIG = ("# preserved comment\n" + "\n".join(k + "=" + v for k, v in ap.EXPECTED.items())
          + "\nssid2=506934\nignore_broadcast_ssid=0\n").encode()
HIDDEN = CONFIG.replace(b"ignore_broadcast_ssid=0", b"ignore_broadcast_ssid=1")
SECRET = "fixture-secret-never-print"
START_DEFINITION = """FragmentPath=/usr/lib/systemd/system/hostapd.service
DropInPaths=/etc/systemd/system/hostapd.service.d/pi4.conf
NeedDaemonReload=no
Type=forking
PIDFile=/run/hostapd.pid
ExecStart={ path=/usr/sbin/hostapd ; argv[]=/usr/sbin/hostapd -B -P /run/hostapd.pid $DAEMON_OPTS ${DAEMON_CONF} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=DAEMON_CONF=/etc/hostapd/hostapd.conf
EnvironmentFiles=/etc/default/hostapd (ignore_errors=yes)
PassEnvironment=
UnsetEnvironment="""


class Runner:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.pid = 123
        self.state = "ENABLED"
        self.service = "active"
        self.bss = "ctrl0"
        self.hidden = 0
        self.job = 0
        self.job_counter = 100
        self.restart_count = 0
        self.unit_exists = False
        self.schedule_fail = False
        self.accept_then_fail = False
        self.not_ready_first = False
        self.hold_first_job = False
        self.external_on_restart = False
        self.restart_hook = None
        self.foreign_job_race = False
        self.start_definition = START_DEFINITION
        self.hooks = {name: "a(sasbttttuii) 0" for name in ap.EXEC_HOOKS}
        self.clock = 0
        self.write_pid()

    def write_pid(self):
        path = self.root / "proc" / str(self.pid) / "cmdline"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"/usr/sbin/hostapd\0-B\0-P\0/run/hostapd.pid\0/etc/hostapd/hostapd.conf\0")

    def sleep(self, amount):
        self.clock += amount

    def finish_job(self):
        self.job = 0
        self.pid += 1
        self.write_pid()
        self.hidden = ap.parse_config((self.root / "etc/hostapd/hostapd.conf").read_bytes())
        self.state = "DISABLED" if self.not_ready_first and self.restart_count == 1 else "ENABLED"

    def __call__(self, args):
        self.calls.append(args[:])
        if args[0] == "/usr/sbin/ip":
            return json.dumps([{"ifname": "ctrl0", "flags": ["UP"],
                                "addr_info": [{"local": "10.78.0.1", "prefixlen": 24}]}])
        if args[0] == "/usr/bin/systemd-run":
            if self.schedule_fail:
                raise ap.APError("fixture scheduling failed")
            self.unit_exists = True
            if self.accept_then_fail:
                raise ap.APError("fixture client timed out after acceptance")
            return ""
        if args[0] == "/usr/bin/systemctl":
            if args[2] == ap.UNIT:
                return "LoadState=loaded\nActiveState=active" if self.unit_exists else "LoadState=not-found\nActiveState=inactive"
            if args[-1] == "--property=Job":
                if self.job and not self.foreign_job_race and not (self.hold_first_job and self.restart_count == 1):
                    self.finish_job()
                return "Job=" + (str(self.job) if self.job else "") + "\n"
            if args[-1] == "--property=" + ap.START_PROPERTIES:
                assert "--all" in args
                return self.start_definition
            return "ActiveState=" + self.service + "\nMainPID=" + str(self.pid)
        if args[:2] == ["/usr/bin/busctl", "get-property"]:
            assert args[2:5] == ["org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/hostapd_2eservice", "org.freedesktop.systemd1.Service"]
            return self.hooks[args[-1]]
        if args[:len(ap.BUS)] == ap.BUS:
            if args[len(ap.BUS)] == "CancelJob":
                assert int(args[-1]) == self.job
                self.job = 0
                return ""
            assert args[len(ap.BUS):] == ["RestartUnit", "ss", "hostapd.service", "fail"]
            if self.foreign_job_race:
                self.job = 777
                raise ap.APError("fixture conflicting foreign job")
            self.restart_count += 1
            self.job_counter += 1
            self.job = self.job_counter
            if self.external_on_restart:
                (self.root / "etc/hostapd/hostapd.conf").write_bytes(HIDDEN + b"# external edit\n")
            if self.restart_hook:
                self.restart_hook()
            return 'o "/org/freedesktop/systemd1/job/' + str(self.job) + '"'
        if args[:5] == ap.CLI:
            if args[5:] == ["status"]:
                return "state=" + self.state + "\nbss[0]=" + self.bss + "\nsecret=" + SECRET
            if args[5:] == ["get", "ignore_broadcast_ssid"]:
                return "FAIL"
        raise AssertionError(args)


class APTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.write("etc/os-release", b"ID=kali\n")
        self.write("etc/hostapd/hostapd.conf", CONFIG, 0o600)
        self.write("etc/hostapd/pi4.psk", SECRET.encode(), 0o600)
        self.write("etc/NetworkManager/conf.d/90-pi4-control.conf", ap.NM_CONFIG.encode())
        self.write("etc/systemd/network/10-pi4-control.link", ap.LINK_CONFIG.encode())
        self.write("usr/lib/systemd/system/hostapd.service", ap.HOSTAPD_UNIT.encode())
        self.write("etc/systemd/system/hostapd.service.d/pi4.conf", ap.HOSTAPD_DROPIN.encode())
        self.write("etc/default/hostapd", b"# no active environment overrides\n")
        self.write(ap.WORKER.lstrip("/"), SOURCE.read_bytes(), 0o755)
        (self.root / "sys/class/net/ctrl0").mkdir(parents=True)
        (self.root / "run/lock").mkdir(parents=True)
        self.runner = Runner(self.root)
        self.system = ap.System(self.root, self.runner, os.getuid(),
                                clock=lambda: self.runner.clock, sleep=self.runner.sleep)

    def write(self, relative, data, mode=0o644):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def invoke(self, *args, euid=0):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = ap.main(list(args), system=self.system, euid=euid)
        self.assertNotIn(SECRET, output.getvalue() + error.getvalue())
        return result, output.getvalue(), error.getvalue()

    def queue(self, value=1):
        self.assertEqual(self.invoke("--invisible" if value else "--visible")[0], 0)

    def record(self):
        return ap.read_record(self.system)

    def test_cli_only_schedules_fixed_worker_and_never_claims_radio_success(self):
        result, output, _ = self.invoke("--invisible")
        self.assertEqual(result, 0)
        self.assertIn("scheduled", output)
        self.assertNotIn("configuration saved", output)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.restart_count, 0)
        command = next(c for c in self.runner.calls if c[0] == "/usr/bin/systemd-run")
        self.assertIn("--unit=" + ap.UNIT, command)
        self.assertIn("--property=User=root", command)
        self.assertIn("--property=ExecStopPost=/usr/bin/python3 -I " + ap.WORKER + " --internal-recover", command)
        self.assertEqual(command[-4:], ["/usr/bin/python3", "-I", ap.WORKER, "--internal-worker"])
        self.assertEqual(stat.S_IMODE((self.root / ap.STATE).stat().st_mode), 0o600)

    def test_worker_persists_restarts_only_hostapd_and_checks_new_pid(self):
        self.queue()
        ap.worker(self.system)
        self.assertEqual(self.record()["state"], "applied")
        self.assertEqual(self.system.config.read_bytes(), HIDDEN)
        self.assertEqual(self.runner.pid, 124)
        self.assertEqual(self.runner.hidden, 1)
        self.assertEqual(self.runner.restart_count, 1)
        self.assertFalse(any("update_beacon" in c or "set" in c for c in self.runner.calls))
        self.assertEqual((self.root / "etc/hostapd/pi4.psk").read_text(), SECRET)
        self.assertEqual(stat.S_IMODE(self.system.config.stat().st_mode), 0o600)

    def test_equal_config_with_broadcast_drift_still_restarts(self):
        self.system.config.write_bytes(HIDDEN)
        self.assertEqual(self.runner.hidden, 0)
        self.queue()
        ap.worker(self.system)
        self.assertEqual(self.runner.restart_count, 1)
        self.assertEqual(self.runner.hidden, 1)

    def test_same_pid_cannot_be_success(self):
        self.queue()
        self.runner.finish_job = lambda: setattr(self.runner, "job", 0)
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertNotEqual(self.record()["state"], "applied")

    def test_readiness_failure_rolls_back_config_and_restarts_original(self):
        self.queue()
        self.runner.not_ready_first = True
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.restart_count, 2)
        self.assertEqual(self.runner.hidden, 0)
        self.assertEqual(self.record()["state"], "recovered")

    def test_timed_out_restart_job_is_cancelled_before_rollback(self):
        self.queue()
        self.runner.hold_first_job = True
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        bus_calls = [c[len(ap.BUS):] for c in self.runner.calls if c[:len(ap.BUS)] == ap.BUS]
        self.assertEqual([c[0] for c in bus_calls], ["RestartUnit", "CancelJob", "RestartUnit"])
        self.assertEqual(bus_calls[1][-1], "101")
        self.assertEqual(self.record()["state"], "recovered")

    def test_external_edit_is_not_overwritten_or_restarted_by_recovery(self):
        self.queue()
        self.runner.external_on_restart = True
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), HIDDEN + b"# external edit\n")
        self.assertEqual(self.runner.restart_count, 1)
        self.assertEqual(self.record()["state"], "failed")

    def test_persist_failure_before_rename_never_restarts(self):
        self.queue()
        self.system.persist = lambda *a: (_ for _ in ()).throw(OSError(SECRET))
        with self.assertRaises(ap.APError) as raised:
            ap.worker(self.system)
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.restart_count, 0)
        self.assertEqual(self.record()["state"], "recovered")

    def test_persist_failure_after_rename_restores_without_unneeded_restart(self):
        self.queue()
        persist = self.system.persist
        calls = 0
        def fail_once(data, expected):
            nonlocal calls
            calls += 1
            persist(data, expected)
            if calls == 1:
                raise OSError(SECRET)
        self.system.persist = fail_once
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.restart_count, 0)

    def test_immediate_prerename_cas_rejects_external_change(self):
        real_replace = ap.os.replace
        real_fsync = ap.os.fsync
        changed = False
        def mutate_after_fsync(fd):
            nonlocal changed
            real_fsync(fd)
            if not changed:
                changed = True
                self.system.config.write_bytes(CONFIG + b"# concurrent\n")
        with patch.object(ap.os, "fsync", mutate_after_fsync), patch.object(ap.os, "replace", wraps=real_replace) as replace:
            with self.assertRaises(ap.APError):
                self.system.persist(HIDDEN, CONFIG)
            replace.assert_not_called()
        self.assertEqual(self.system.config.read_bytes(), CONFIG + b"# concurrent\n")

    def test_exec_stop_post_recovers_crashed_worker_after_persist(self):
        self.queue()
        record = self.record()
        record.update(state="running", phase="restart", original=base64.b64encode(CONFIG).decode())
        ap.write_record(self.system, record)
        self.system.config.write_bytes(HIDDEN)
        ap.worker(self.system, recovery=True)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.record()["state"], "recovered")
        self.assertEqual(self.runner.restart_count, 1)

    def test_success_exec_stop_post_has_no_second_restart(self):
        self.queue()
        ap.worker(self.system)
        ap.worker(self.system, recovery=True)
        self.assertEqual(self.runner.restart_count, 1)
        self.assertEqual(self.record()["state"], "applied")

    def test_duplicate_queue_is_rejected_without_overwriting_request(self):
        self.queue()
        original = (self.root / ap.STATE).read_bytes()
        self.assertEqual(self.invoke("--visible")[0], 1)
        self.assertEqual((self.root / ap.STATE).read_bytes(), original)

    def test_worker_mismatch_is_rejected(self):
        self.write(ap.WORKER.lstrip("/"), b"unrecognized worker")
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_nonroot_changes_and_direct_internal_worker_are_rejected(self):
        self.assertEqual(self.invoke("--invisible", euid=1000)[0], 77)
        self.assertEqual(self.invoke("--internal-worker", euid=1000)[0], 77)
        self.assertEqual(self.invoke("--internal-worker")[0], 1)
        self.assertEqual(self.runner.restart_count, 0)

    def test_unknown_platform_is_rejected_before_queue(self):
        self.write("etc/os-release", b"ID=debian\n")
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(self.runner.calls, [])

    def test_status_is_read_only_and_radio_honest(self):
        code, output, _ = self.invoke("--status")
        self.assertEqual(code, 0)
        self.assertIn("Configured visibility: visible", output)
        self.assertIn("not independently verified", output)
        self.assertFalse((self.root / ap.STATE).exists())
        self.assertFalse((self.root / "run/lock/automations-ap.lock").exists())

    def test_schedule_failure_before_acceptance_releases_record(self):
        self.runner.schedule_fail = True
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(self.record()["state"], "recovered")
        self.assertEqual(self.system.config.read_bytes(), CONFIG)

    def test_client_failure_after_acceptance_does_not_cancel_worker(self):
        self.runner.accept_then_fail = True
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(self.record()["state"], "queued")
        ap.worker(self.system)
        self.assertEqual(self.record()["state"], "applied")

    def test_tampered_record_and_symlink_are_rejected(self):
        self.queue()
        path = self.root / ap.STATE
        record = json.loads(path.read_text())
        record["target"] = "1; arbitrary command"
        path.write_text(json.dumps(record))
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        path.unlink()
        path.symlink_to(self.system.config)
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.runner.restart_count, 0)

    def test_keyboard_interrupt_during_restart_still_recovers(self):
        self.queue()
        def interrupt_once():
            self.runner.restart_hook = None
            raise KeyboardInterrupt()
        self.runner.restart_hook = interrupt_once
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.record()["state"], "recovered")
        self.assertEqual(self.system.config.read_bytes(), CONFIG)

    def test_native_empty_job_and_reject_missing_negative_or_foreign_format(self):
        self.assertEqual(ap.current_job(self.system), 0)
        for response in ("Job=-1", "", "Other=0", "Job=one", "Job=4294967296"):
            with self.subTest(response=response):
                with patch.object(self.system, "runner", return_value=response):
                    with self.assertRaises(ap.APError):
                        ap.current_job(self.system)

    def test_actual_readonly_pi_definition_is_accepted(self):
        observed = json.loads((HERE / "fixtures/hostapd-definition-systemd262.json").read_text())
        self.assertEqual(observed["properties_all"]["exit"], 0)
        self.runner.start_definition = observed["properties_all"]["stdout"].strip()
        for hook in ap.EXEC_HOOKS:
            self.assertEqual(observed["dbus_hooks"][hook]["exit"], 0)
            self.runner.hooks[hook] = observed["dbus_hooks"][hook]["stdout"].strip()
        sections = observed["unit"]["stdout"].split("# /etc/systemd/system/hostapd.service.d/pi4.conf\n")
        self.write("usr/lib/systemd/system/hostapd.service", sections[0].encode())
        self.write("etc/systemd/system/hostapd.service.d/pi4.conf", sections[1].encode())
        ap.verify_start_definition(self.system)
        self.assertEqual(self.runner.restart_count, 0)

    def test_conflicting_job_race_is_not_replaced_or_cancelled(self):
        self.queue()
        self.runner.foreign_job_race = True
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.runner.job, 777)
        self.assertEqual(self.runner.restart_count, 0)
        bus_calls = [c[len(ap.BUS):] for c in self.runner.calls if c[:len(ap.BUS)] == ap.BUS]
        self.assertEqual(bus_calls, [["RestartUnit", "ss", "hostapd.service", "fail"]])
        self.assertEqual(self.record()["state"], "failed")

    def test_correct_current_pid_but_unknown_next_start_is_rejected(self):
        alternatives = (
            START_DEFINITION + "\nExecStartPre={ path=/bin/false ; }",
            START_DEFINITION.replace("NeedDaemonReload=no", "NeedDaemonReload=yes"),
            START_DEFINITION.replace("pi4.conf", "pi4.conf /etc/systemd/system/hostapd.service.d/other.conf"),
            START_DEFINITION.replace("argv[]=/usr/sbin/hostapd", "argv[]=/usr/sbin/hostapd -f /tmp/other"),
        )
        for definition in alternatives:
            with self.subTest(definition=definition):
                self.runner.start_definition = definition
                self.assertEqual(self.invoke("--invisible")[0], 1)
                self.assertFalse((self.root / ap.STATE).exists())
                self.assertEqual(self.runner.restart_count, 0)
                self.assertEqual(self.system.config.read_bytes(), CONFIG)

    def test_worker_rechecks_start_definition_before_any_persist(self):
        self.queue()
        self.runner.hooks["ExecStopPost"] = "a(sasbttttuii) 1 arbitrary command"
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.restart_count, 0)

    def test_external_config_before_worker_does_not_claim_restoration(self):
        self.queue()
        changed = CONFIG + b"# independently edited before worker\n"
        self.system.config.write_bytes(changed)
        with self.assertRaises(ap.APError):
            ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), changed)
        self.assertEqual(self.runner.restart_count, 0)
        result, output, _ = self.invoke("--status")
        self.assertEqual(result, 0)
        self.assertIn("no configuration change was made", output)
        self.assertNotIn("restored", output)

    def test_foreign_environment_and_unit_files_cannot_be_used(self):
        for relative, data in (
            ("etc/default/hostapd", b'\xff' + SECRET.encode()),
            ("etc/default/hostapd", b'DAEMON_OPTS="-f /tmp/other"\n'),
            ("usr/lib/systemd/system/hostapd.service", ap.HOSTAPD_UNIT.encode() + b"\nExecStartPost=/bin/false\n"),
            ("etc/systemd/system/hostapd.service.d/pi4.conf", ap.HOSTAPD_DROPIN.encode() + b"\nExecStopPost=/bin/false\n"),
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(data)
                self.assertEqual(self.invoke("--invisible")[0], 1)
                self.assertFalse((self.root / ap.STATE).exists())
                path.write_bytes(original)

    def test_bare_command_means_status_not_help(self):
        result, output, _ = self.invoke(euid=1000)
        self.assertEqual(result, 0)
        self.assertIn("Live AP state", output)
        self.assertNotIn("usage:", output)

    def test_help_never_reads_configuration_or_requires_root(self):
        self.system.validate = lambda: self.fail("help read system configuration")
        with self.assertRaises(SystemExit) as result, redirect_stdout(io.StringIO()):
            ap.main(["--help"], system=self.system, euid=1000)
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(self.runner.calls, [])

    def test_unknown_and_conflicting_flags_are_usage_errors(self):
        for args in [["--root", "/tmp"], ["--visible", "--invisible"], ["--off"], ["--status", "--visible"]]:
            with self.subTest(args=args), self.assertRaises(SystemExit) as result, redirect_stderr(io.StringIO()):
                ap.main(args, system=self.system)
            self.assertEqual(result.exception.code, 64)
        self.assertEqual(self.runner.calls, [])

    def test_unknown_config_is_rejected_without_runtime_commands(self):
        for config in [CONFIG + b"bss=other0\n", CONFIG.replace(b"interface=ctrl0", b"interface=wlan0"),
                       CONFIG + b"ignore_broadcast_ssid=1\n", HIDDEN.replace(b"ignore_broadcast_ssid=1", b"ignore_broadcast_ssid=2"),
                       CONFIG + b"wpa_passphrase=" + SECRET.encode() + b"\n"]:
            with self.subTest(config=config):
                self.system.config.write_bytes(config)
                self.assertEqual(self.invoke("--invisible")[0], 1)
                self.assertEqual(self.system.config.read_bytes(), config)
                self.assertEqual(self.runner.calls, [])

    def test_wrong_networkmanager_ownership_is_rejected(self):
        self.write("etc/NetworkManager/conf.d/90-pi4-control.conf", b"[device-pi4-control]\nmanaged=1\n")
        self.assertEqual(self.invoke("--visible")[0], 1)
        self.assertEqual(self.runner.restart_count, 0)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_unknown_current_hostapd_configuration_is_rejected(self):
        self.write("proc/123/cmdline", b"/usr/sbin/hostapd\0/etc/other.conf\0")
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_wrong_runtime_bss_is_rejected(self):
        self.runner.bss = "wlan0"
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_disabled_ap_is_reported_but_never_started(self):
        self.runner.service = "inactive"
        code, output, _ = self.invoke("--status")
        self.assertEqual(code, 0)
        self.assertIn("hostapd service: inactive", output)
        self.assertEqual(self.invoke("--visible")[0], 1)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_missing_interface_is_reported_and_not_created(self):
        (self.root / "sys/class/net/ctrl0").rmdir()
        code, output, _ = self.invoke("--status")
        self.assertEqual(code, 0)
        self.assertIn("Interface present: no", output)
        self.assertEqual(self.invoke("--visible")[0], 1)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_concurrent_caller_is_rejected(self):
        with self.system.lock():
            code, _, error = self.invoke("--invisible")
        self.assertEqual(code, 1)
        self.assertIn("Another AP operation", error)
        self.assertFalse((self.root / ap.STATE).exists())

    def test_symlink_config_and_lock_are_rejected(self):
        original = self.root / "etc/hostapd/original.conf"
        self.system.config.rename(original)
        self.system.config.symlink_to(original)
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(original.read_bytes(), CONFIG)
        self.system.config.unlink()
        original.rename(self.system.config)
        lock = self.root / "run/lock/automations-ap.lock"
        lock.unlink()
        lock.symlink_to(self.system.config)
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)

    def test_writable_or_hardlinked_config_is_rejected(self):
        self.system.config.chmod(0o666)
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.system.config.chmod(0o600)
        os.link(self.system.config, self.root / "other.conf")
        self.assertEqual(self.invoke("--invisible")[0], 1)
        self.assertEqual(self.runner.restart_count, 0)

    def test_visible_worker_restores_only_ssid_setting(self):
        self.system.config.write_bytes(HIDDEN)
        self.runner.hidden = 1
        self.queue(value=0)
        ap.worker(self.system)
        self.assertEqual(self.system.config.read_bytes(), CONFIG)
        self.assertEqual(self.runner.hidden, 0)
        self.assertEqual(self.runner.restart_count, 1)


if __name__ == "__main__":
    unittest.main()
