"""Host profiles select only trusted host backends, with no legacy fallback."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("host_dispatch_tests", ROOT / "common/python/auto.py")
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class HostDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner_uid = os.getuid()
        self.commands = self.root / "commands"
        self.backends = self.root / cli.HOST_DIRECTORY
        self.helper = self.root / cli.PROFILE_HELPER
        self.profile = self.root / cli.PROFILE_PATH
        for directory in (self.commands, self.backends, self.helper.parent, self.profile.parent):
            directory.mkdir(parents=True, exist_ok=True)
        for directory in self.root.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        self.helper.write_bytes((ROOT / "common/python/platform_support.py").read_bytes())
        self.helper.chmod(0o644)
        self.data = {
            "schema_version": 1, "platform": "kali-host",
            "protected_interfaces": ["enp0s3"], "ssh_service": "ssh.service",
        }
        self.write_profile()
        self.calls = []

    def write_profile(self):
        self.profile.write_text(json.dumps(self.data))
        self.profile.chmod(0o644)

    def payload(self, name, *, host=False, content="#!/bin/sh\nexit 0\n", mode=0o755):
        path = (self.backends if host else self.commands) / name
        path.write_text(content)
        path.chmod(mode)
        return path

    def invoke(self, args, *, owner_uid=None):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cli.main(
                args, directory=self.commands, execute=lambda *values: self.calls.append(values),
                _profile_root=self.root,
                _owner_uid=self.owner_uid if owner_uid is None else owner_uid,
            )
        return code, output.getvalue(), errors.getvalue()

    def test_configured_host_routes_only_to_host_backend_with_literal_arguments(self):
        self.payload("wifi")
        backend = self.payload("wifi", host=True)
        args = ["wifi", "two words", "", "$(touch never)", "*", "--interface", "wlan1"]
        code, _, error = self.invoke(args)
        self.assertEqual(code, 0, error)
        self.assertEqual(self.calls[0][:2], (str(backend), [str(backend), *args[1:]]))
        self.assertEqual(len(self.calls), 1)

    def test_host_dispatch_keeps_system_path_and_english_locale(self):
        self.payload("cert")
        self.payload("cert", host=True)
        with patch.dict(os.environ, {"PATH": "/tmp/untrusted", "LC_ALL": "de_DE.UTF-8"}):
            code, _, error = self.invoke(["cert", "--help"])
            self.assertEqual(os.environ["PATH"], "/tmp/untrusted")
        self.assertEqual(code, 0, error)
        self.assertEqual(self.calls[0][2]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(self.calls[0][2]["LC_ALL"], "C")

    def test_missing_host_backend_returns_unavailable_without_legacy_execution(self):
        self.payload("ssh")
        code, _, error = self.invoke(["ssh", "--off"])
        self.assertEqual(code, 69)
        self.assertIn("unavailable", error)
        self.assertEqual(self.calls, [])

    def test_help_lists_intersection_without_executing_any_module(self):
        marker = self.root / "must-not-exist"
        body = "#!/bin/sh\ntouch " + str(marker) + "\n"
        self.payload("cert", content=body)
        self.payload("cert", host=True, content=body)
        self.payload("ssh", content=body)
        self.payload("wifi", host=True, content=body)
        for args in ([], ["--help"]):
            with self.subTest(args=args):
                code, output, error = self.invoke(args)
                self.assertEqual(code, 0, error)
                self.assertIn("  cert\n", output)
                self.assertNotIn("  ssh\n", output)
                self.assertNotIn("  wifi\n", output)
        self.assertFalse(marker.exists())
        self.assertEqual(self.calls, [])

    def test_backend_without_installed_module_is_still_unknown(self):
        self.payload("wifi", host=True)
        code, _, error = self.invoke(["wifi", "--help"])
        self.assertEqual(code, 64)
        self.assertIn("not installed", error)
        self.assertEqual(self.calls, [])

    def test_empty_host_help_reports_unavailable_backends_honestly(self):
        self.payload("cert")
        code, output, error = self.invoke(["--help"])
        self.assertEqual(code, 0, error)
        self.assertIn("No installed commands have an available kali-host backend.", output)
        self.assertEqual(self.calls, [])

    def test_unsafe_or_malformed_profile_never_falls_back(self):
        self.payload("cert")
        self.payload("cert", host=True)
        self.profile.write_text("{not-json")
        self.profile.chmod(0o644)
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        self.write_profile()
        self.profile.chmod(0o666)
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_existing_or_dangling_profile_symlink_never_selects_legacy(self):
        self.payload("cert")
        self.payload("cert", host=True)
        self.profile.unlink()
        for target in (self.root / "absent", self.helper):
            with self.subTest(target=target):
                self.profile.symlink_to(target)
                code, _, _ = self.invoke(["cert", "--on"])
                self.assertEqual(code, 1)
                self.profile.unlink()
        self.assertEqual(self.calls, [])

    def test_missing_helper_fails_closed_even_for_help(self):
        self.payload("cert")
        self.helper.unlink()
        code, _, error = self.invoke(["--help"])
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", error)
        self.assertEqual(self.calls, [])

    def test_unsafe_helper_is_rejected_before_import(self):
        marker = self.root / "helper-must-not-run"
        self.helper.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        self.helper.chmod(0o666)
        self.payload("cert")
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        self.assertFalse(marker.exists())
        self.assertEqual(self.calls, [])

    def test_symlink_helper_is_rejected(self):
        real = self.root / "actual-helper.py"
        real.write_bytes(self.helper.read_bytes())
        real.chmod(0o644)
        self.helper.unlink()
        self.helper.symlink_to(real)
        self.payload("cert")
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_helper_ownership_and_parent_permissions_are_enforced(self):
        self.payload("cert")
        code, _, _ = self.invoke(["cert", "--on"], owner_uid=self.owner_uid + 1)
        self.assertEqual(code, 1)
        self.helper.parent.chmod(0o777)
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_unconfigured_or_wrong_platform_profile_cannot_route(self):
        self.payload("cert")
        self.payload("cert", host=True)
        for result in (
            "platform='kali-host'; configured=False",
            "platform='pi4'; configured=True",
        ):
            with self.subTest(result=result):
                self.helper.write_text(
                    "class Result:\n    " + result + "\n"
                    "def load_profile(**kwargs):\n    return Result()\n"
                )
                self.helper.chmod(0o644)
                code, _, _ = self.invoke(["cert", "--on"])
                self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_unsafe_backend_is_not_executed_and_symlinks_are_unavailable(self):
        self.payload("cert")
        backend = self.payload("cert", host=True, mode=0o777)
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 1)
        backend.unlink()
        backend.symlink_to(self.commands / "cert")
        code, _, _ = self.invoke(["cert", "--on"])
        self.assertEqual(code, 69)
        self.assertEqual(self.calls, [])

    def test_missing_profile_preserves_legacy_dispatch_and_ignores_host_helper(self):
        legacy = self.payload("cert")
        self.payload("cert", host=True)
        self.profile.unlink()
        self.helper.write_text("raise RuntimeError('must not import')\n")
        self.helper.chmod(0o666)
        with patch.object(cli.os, "geteuid", return_value=1000):
            code, _, error = self.invoke(["cert", "--help", "literal value"])
        self.assertEqual(code, 0, error)
        self.assertEqual(
            self.calls[0][:2], (str(legacy), [str(legacy), "--help", "literal value"])
        )

    def test_missing_profile_preserves_legacy_help(self):
        self.payload("cert")
        self.payload("ssh")
        self.payload("cert", host=True)
        self.profile.unlink()
        code, output, error = self.invoke(["--help"])
        self.assertEqual(code, 0, error)
        self.assertIn("  cert\n", output)
        self.assertIn("  ssh\n", output)
        self.assertEqual(self.calls, [])

    def test_real_host_dispatch_preserves_child_exit_status(self):
        self.payload("cert")
        self.payload("cert", host=True, content="#!/bin/sh\nexit 7\n")
        script = (
            "import importlib.util,sys; "
            "s=importlib.util.spec_from_file_location('cli',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "sys.exit(m.main(['cert'],directory=m.Path(sys.argv[2]),"
            "_profile_root=m.Path(sys.argv[3]),_owner_uid=int(sys.argv[4])))"
        )
        result = subprocess.run(
            ["/usr/bin/python3", "-B", "-c", script, str(ROOT / "common/python/auto.py"),
             str(self.commands), str(self.root), str(self.owner_uid)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 7, result.stderr)


if __name__ == "__main__":
    unittest.main()
