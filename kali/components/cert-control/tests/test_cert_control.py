import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("auto_cert", ROOT / "python/auto_cert.py")
cert = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cert)

# Exact route layout from the accepted builder, without importing that repository.
DOWNLOAD = """
        alias /etc/pi4/tls/ca.crt;
        default_type application/x-x509-ca-cert;
        add_header Content-Disposition 'attachment; filename="pi4-ca.crt"';
    """
BASE = """# A brace in a comment must not become a block: {
map_hash_bucket_size 64;
map $http_upgrade $pi4_connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 0.0.0.0:80 default_server;
    server_name _;
    access_log off;
    location = /cert {BODY}
    location = /pi4-ca.crt {BODY}
    location / { return 404; }
}
server {
    listen 0.0.0.0:443 ssl default_server;
    server_name _;
    ssl_certificate /etc/pi4/tls/server.crt;
    ssl_certificate_key /etc/pi4/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;
    location = /cert {BODY}
    location = / { return 302 /remote/; }
    location = /remote { return 301 /remote/; }
    location /remote/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $pi4_connection_upgrade;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
    location / { return 404; }
}
""".replace("BODY", DOWNLOAD)


class FakeRunner:
    def __init__(self, *, state="active", tests=None, reloads=None, states=None):
        self.state = state
        self.tests = list(tests or [])
        self.reloads = list(reloads or [])
        self.states = list(states or [])
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["nginx", "-t"]:
            code = self.tests.pop(0) if self.tests else 0
            if isinstance(code, BaseException):
                raise code
            return subprocess.CompletedProcess(args, code, "", "")
        if args[:2] == ["systemctl", "reload"]:
            code = self.reloads.pop(0) if self.reloads else 0
            return subprocess.CompletedProcess(args, code, "", "")
        if args[:2] == ["systemctl", "show"]:
            state = self.states.pop(0) if self.states else self.state
            return subprocess.CompletedProcess(args, 0, state + "\n", "")
        raise AssertionError(args)

    @property
    def reload_count(self):
        return sum(args[:2] == ["systemctl", "reload"] for args in self.calls)


class ParsingTests(unittest.TestCase):
    def test_exact_three_routes_and_initial_enabled_state(self):
        self.assertEqual([item[0] for item in cert.routes(BASE)],
                         ["http /cert", "http /pi4-ca.crt", "https /cert"])
        self.assertEqual(cert.configured_state(BASE), "on")

    def test_off_and_on_preserve_every_byte_outside_download_bodies(self):
        def outside(text):
            for _, block, _ in sorted(cert.routes(text), key=lambda item: item[1].body_start, reverse=True):
                text = text[:block.body_start] + "<download>" + text[block.body_end:]
            return text
        disabled = cert.transform(BASE, False)
        enabled = cert.transform(disabled, True)
        self.assertEqual(cert.configured_state(disabled), "off")
        self.assertEqual(cert.configured_state(enabled), "on")
        self.assertEqual(outside(BASE), outside(disabled))
        self.assertEqual(outside(BASE), outside(enabled))
        self.assertIn("ssl_certificate_key /etc/pi4/tls/server.key;", disabled)
        self.assertIn("proxy_pass http://127.0.0.1:8080;", disabled)
        self.assertEqual(disabled.count("return 404;"), BASE.count("return 404;") + 3)

    def test_idempotent_bytes_both_directions(self):
        self.assertEqual(cert.transform(BASE, True), BASE)
        disabled = cert.transform(BASE, False)
        self.assertEqual(cert.transform(disabled, False), disabled)

    def test_mixed_configuration_can_be_normalized(self):
        block = cert.routes(BASE)[0][1]
        mixed = BASE[:block.body_start] + cert.OFF_BODY + BASE[block.body_end:]
        self.assertEqual(cert.configured_state(mixed), "mixed")
        self.assertEqual(cert.configured_state(cert.transform(mixed, False)), "off")
        self.assertEqual(cert.configured_state(cert.transform(mixed, True)), "on")

    def test_unknown_alias_or_extra_directive_rejected(self):
        for bad in (BASE.replace("/etc/pi4/tls/ca.crt", "/private/secret.key", 1),
                    BASE.replace("alias /etc/pi4/tls/ca.crt;", "alias /etc/pi4/tls/ca.crt; autoindex on;", 1)):
            with self.subTest(bad=bad[:30]), self.assertRaises(cert.CertError):
                cert.transform(bad, False)

    def test_missing_duplicate_or_prefix_route_rejected(self):
        variants = [
            BASE.replace("location = /cert", "location = /other", 1),
            BASE.replace("location = /pi4-ca.crt", "location = /cert", 1),
            BASE.replace("location = /cert", "location /cert", 1),
            BASE.replace("location = /cert", "location = /cert {return 404;} location = /cert", 1),
        ]
        for bad in variants:
            with self.subTest(bad=bad[:30]), self.assertRaises(cert.CertError):
                cert.transform(bad, False)

    def test_unexpected_or_duplicate_listener_rejected(self):
        variants = [
            BASE.replace("0.0.0.0:80", "127.0.0.1:80"),
            BASE.replace("listen 0.0.0.0:80 default_server;",
                         "listen 0.0.0.0:80 default_server; listen [::]:80;"),
            BASE.replace("listen 0.0.0.0:443 ssl default_server;", "listen 0.0.0.0:80 default_server;"),
        ]
        for bad in variants:
            with self.subTest(bad=bad[:30]), self.assertRaises(cert.CertError):
                cert.transform(bad, False)

    def test_malformed_quotation_and_braces_rejected(self):
        for bad in (BASE[:-2], BASE + "}", BASE + "pending", BASE + "x 'unterminated"):
            with self.subTest(bad=bad[-30:]), self.assertRaises(cert.CertError):
                cert.transform(bad, False)

    def test_nested_target_directive_rejected(self):
        with self.assertRaises(cert.CertError):
            cert.transform(BASE.replace("alias /etc/pi4/tls/ca.crt;",
                                        "if ($x) { return 404; } alias /etc/pi4/tls/ca.crt;", 1), False)

    def test_quotes_and_comments_cannot_forge_braces_or_locations(self):
        configured = BASE.replace("server_name _;", 'server_name "brace}#not-comment";', 1)
        self.assertEqual(len(cert.routes(configured)), 3)
        disabled = cert.transform(configured, False)
        self.assertIn('server_name "brace}#not-comment";', disabled)

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(cert.CertError):
            cert.decode(b"\xff")


class ChangeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "pi4-remote.conf"
        self.lock = self.root / "cert.lock"
        self.config.write_text(BASE)
        self.config.chmod(0o640)

    def tearDown(self):
        self.temporary.cleanup()

    def change(self, enabled=False, runner=None):
        return cert.change(enabled, config=self.config, lock=self.lock, runner=runner or FakeRunner())

    def test_active_service_validate_then_reload_and_preserve_permissions(self):
        before = self.config.stat()
        runner = FakeRunner()
        message = self.change(runner=runner)
        after = self.config.stat()
        self.assertEqual(cert.configured_state(self.config.read_text()), "off")
        self.assertEqual((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
                         (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)))
        self.assertEqual(runner.calls, [
            ["systemctl", "show", "nginx.service", "--property=ActiveState", "--value"],
            ["nginx", "-t"], ["nginx", "-t"],
            ["systemctl", "reload", "nginx.service"],
            ["systemctl", "show", "nginx.service", "--property=ActiveState", "--value"]])
        self.assertIn("reloaded", message)
        self.assertEqual(list(self.root.glob(".auto-cert-*")), [])

    def test_idempotent_does_not_validate_or_reload(self):
        runner = FakeRunner()
        original = self.config.read_bytes()
        message = self.change(True, runner)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("Already", message)

    def test_inactive_service_saved_but_never_started_or_reloaded(self):
        runner = FakeRunner(state="inactive")
        message = self.change(runner=runner)
        self.assertEqual(cert.configured_state(self.config.read_text()), "off")
        self.assertEqual(runner.reload_count, 0)
        self.assertIn("was not started", message)
        self.assertFalse(any("start" in args or "stop" in args for args in runner.calls))

    def test_failed_service_state_is_not_reported_live(self):
        runner = FakeRunner(state="failed")
        self.assertIn("nginx is failed", self.change(runner=runner))
        self.assertEqual(runner.reload_count, 0)
        self.assertIn("not a live route probe", cert.describe("off", "failed"))

    def test_service_transition_rejected_before_write(self):
        runner = FakeRunner(state="activating")
        with self.assertRaises(cert.CertError):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)
        self.assertEqual(len(runner.calls), 1)

    def test_invalid_existing_configuration_does_not_write(self):
        runner = FakeRunner(tests=[1])
        with self.assertRaisesRegex(cert.CertError, "existing"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)
        self.assertEqual(runner.reload_count, 0)

    def test_candidate_validation_failure_restores_bytes_without_reload(self):
        runner = FakeRunner(tests=[0, 1, 0])
        with self.assertRaisesRegex(cert.CertError, "Original configuration restored"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)
        self.assertEqual(runner.reload_count, 0)

    def test_reload_failure_restores_and_reloads_original(self):
        runner = FakeRunner(reloads=[1, 0])
        with self.assertRaisesRegex(cert.CertError, "Original configuration restored"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)
        self.assertEqual(runner.reload_count, 2)

    def test_service_failure_after_reload_restores_original(self):
        runner = FakeRunner(states=["active", "failed", "active"])
        with self.assertRaisesRegex(cert.CertError, "Original configuration restored"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)
        self.assertEqual(runner.reload_count, 2)

    def test_failed_rollback_reload_is_explicit(self):
        runner = FakeRunner(reloads=[1, 1])
        with self.assertRaisesRegex(cert.CertError, "Rollback needs attention"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)

    def test_runner_failure_after_write_rolls_back(self):
        runner = FakeRunner(tests=[0, cert.CertError("timeout"), 0])
        with self.assertRaisesRegex(cert.CertError, "Original configuration restored"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)

    def test_interrupted_candidate_validation_rolls_back(self):
        runner = FakeRunner(tests=[0, KeyboardInterrupt(), 0])
        with self.assertRaisesRegex(cert.CertError, "Operation interrupted.*restored"):
            self.change(runner=runner)
        self.assertEqual(self.config.read_text(), BASE)

    def test_atomic_failure_after_rename_rolls_back(self):
        original_replace = cert.atomic_replace
        calls = []
        def write_then_fail(path, data, expected, metadata):
            original_replace(path, data, expected, metadata)
            calls.append(data)
            if len(calls) == 1:
                raise OSError("directory sync failed")
        with patch.object(cert, "atomic_replace", side_effect=write_then_fail):
            with self.assertRaisesRegex(cert.CertError, "Original configuration restored"):
                self.change()
        self.assertEqual(self.config.read_text(), BASE)

    def test_external_edit_during_failure_is_not_lost(self):
        runner = FakeRunner()
        def edit_during_reload(args):
            if args[:2] == ["systemctl", "reload"]:
                self.config.write_text(BASE + "# concurrent edit\n")
                return subprocess.CompletedProcess(args, 1, "", "")
            return runner(args)
        with self.assertRaisesRegex(cert.CertError, "Rollback needs attention.*externally"):
            self.change(runner=edit_during_reload)
        self.assertTrue(self.config.read_text().endswith("# concurrent edit\n"))

    def test_configuration_symlink_rejected(self):
        real = self.root / "real"
        self.config.rename(real)
        self.config.symlink_to(real)
        with self.assertRaises(cert.CertError):
            self.change()
        self.assertEqual(real.read_text(), BASE)

    def test_lock_symlink_rejected(self):
        target = self.root / "target"
        target.write_text("unchanged")
        self.lock.symlink_to(target)
        with self.assertRaises(OSError):
            self.change()
        self.assertEqual(target.read_text(), "unchanged")
        self.assertEqual(self.config.read_text(), BASE)

    def test_serialized_operations_reject_second_caller(self):
        with cert.exclusive_lock(self.lock):
            with self.assertRaisesRegex(cert.CertError, "Another"):
                self.change()
        self.assertEqual(self.config.read_text(), BASE)

    def test_external_edit_not_overwritten(self):
        original, metadata = cert.read_config(self.config)
        self.config.write_text(BASE + "# edited elsewhere\n")
        with self.assertRaisesRegex(cert.CertError, "concurrently"):
            cert.atomic_replace(self.config, b"candidate", original, metadata)
        self.assertTrue(self.config.read_text().endswith("# edited elsewhere\n"))

    def test_overlarge_file_rejected(self):
        self.config.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(cert.CertError):
            cert.read_config(self.config)


class CLITests(unittest.TestCase):
    def test_service_commands_use_fixed_path_and_english_locale(self):
        with patch.dict(cert.os.environ, {"PATH": "/untrusted", "LC_ALL": "de_DE.UTF-8"}), \
             patch.object(cert.subprocess, "run") as run:
            cert.run_command(["nginx", "-t"])
        self.assertEqual(run.call_args.kwargs["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")

    def test_help_does_not_require_root_or_read_config(self):
        with patch.object(cert.os, "geteuid", return_value=1000), patch.object(cert, "read_config") as read:
            with self.assertRaises(SystemExit) as result:
                cert.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        read.assert_not_called()

    def test_change_requires_root_before_any_read_or_command(self):
        with patch.object(cert.os, "geteuid", return_value=1000), patch.object(cert, "change") as change:
            self.assertEqual(cert.main(["--off"]), 1)
        change.assert_not_called()

    def test_bare_command_defaults_to_read_only_status(self):
        metadata = os.stat(__file__)
        with patch.object(cert, "read_config", return_value=(BASE.encode(), metadata)), \
             patch.object(cert, "service_state", return_value="inactive"), patch.object(cert, "change") as change:
            self.assertEqual(cert.main([]), 0)
        change.assert_not_called()

    def test_conflicting_operations_rejected(self):
        with self.assertRaises(SystemExit) as result:
            cert.main(["--on", "--off"])
        self.assertEqual(result.exception.code, 2)

    def test_no_path_override_exposed(self):
        with self.assertRaises(SystemExit) as result:
            cert.main(["--config", "/tmp/other"])
        self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
