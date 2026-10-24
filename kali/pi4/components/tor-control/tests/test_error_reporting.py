"""CLI error trust boundary; no network, service or filesystem mutations."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("tor_error_reporting", ROOT / "pi4/python/auto_tor.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
MESSAGE = "Enable a healthy explicit auto share uplink before anonymity."
RUNTIME = ("class Error(RuntimeError): pass\n"
           "class Runtime:\n"
           "    def status(self): return {'mode':'off','ready':False}\n"
           "    def operation(self, mode): raise Error(" + repr(MESSAGE) + ")\n").encode()
RUNTIME_BUSY = RUNTIME.replace(b"class Runtime:\n", b"class Busy(Error): pass\nclass Runtime:\n    Busy = Busy\n")


def load():
    return module.load_egress()


class ErrorReportingTests(unittest.TestCase):
    def setUp(self):
        module._SHARED_RUNTIME_ERROR = None
        module._SHARED_RUNTIME_BUSY = None

    def capture(self, error):
        output = io.StringIO()
        with patch.object(module, "main", side_effect=error), contextlib.redirect_stderr(output):
            self.assertEqual(module.cli(["--on"]), 1)
        return output.getvalue()

    def test_real_entrypoint_reports_trusted_shared_preflight_error(self):
        output = io.StringIO()
        with patch.object(module.os, "geteuid", return_value=0), \
                patch.object(module, "trusted_read", return_value=RUNTIME), \
                patch.object(module, "Platform") as platform, contextlib.redirect_stderr(output):
            self.assertEqual(module.cli(["--on"]), 1)
        self.assertEqual(output.getvalue(), "Error: " + MESSAGE + "\n")
        platform.return_value.assert_not_called()
        self.assertEqual(platform.return_value.method_calls, [])

    def test_own_known_error_remains_readable(self):
        self.assertEqual(self.capture(module.Error("Expected safe message.")), "Error: Expected safe message.\n")

    def test_trusted_busy_remains_a_public_cli_error_with_readable_text(self):
        with patch.object(module, "trusted_read", return_value=RUNTIME_BUSY):
            runtime = load()
        self.assertIs(module._SHARED_RUNTIME_BUSY, runtime.Busy)
        self.assertEqual(self.capture(runtime.Busy("Another sharing operation is running.")),
                         "Error: Another sharing operation is running.\n")

    def test_failed_import_cannot_reuse_a_previous_trusted_busy(self):
        with patch.object(module, "trusted_read", return_value=RUNTIME_BUSY):
            busy = load().Busy
        with patch.object(module, "trusted_read", side_effect=OSError("PRIVATE_CONFIGURATION_SENTINEL")):
            with self.assertRaises(OSError):
                load()
        self.assertIsNone(module._SHARED_RUNTIME_BUSY)
        self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", self.capture(busy("PRIVATE_CONFIGURATION_SENTINEL")))

    def test_unknown_busy_subclass_is_not_trusted(self):
        with patch.object(module, "trusted_read", return_value=RUNTIME_BUSY):
            busy = load().Busy
        foreign = type("Foreign", (busy,), {})
        self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", self.capture(foreign("PRIVATE_CONFIGURATION_SENTINEL")))

    def test_busy_must_be_a_distinct_error_with_the_runtime_alias(self):
        invalid = RUNTIME.replace(b"class Runtime:\n", b"Busy = Error\nclass Runtime:\n    Busy = Busy\n")
        with patch.object(module, "trusted_read", return_value=invalid):
            with self.assertRaisesRegex(module.Error, "lock interface"):
                load()
        self.assertIsNone(module._SHARED_RUNTIME_ERROR)
        self.assertIsNone(module._SHARED_RUNTIME_BUSY)

    def test_arbitrary_exception_text_is_hidden(self):
        for error_type in (RuntimeError, OSError, ValueError, KeyError, Exception):
            with self.subTest(error=error_type):
                output = self.capture(error_type("PRIVATE_CONFIGURATION_SENTINEL"))
                self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", output)
                self.assertNotIn("Traceback", output)
                self.assertIn("could not be completed safely", output)

    def test_class_name_or_module_name_is_not_trust(self):
        forged = type("Error", (RuntimeError,), {"__module__": "automations_egress"})
        self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", self.capture(forged("PRIVATE_CONFIGURATION_SENTINEL")))

    def test_failed_import_cannot_reuse_previous_trusted_error(self):
        with patch.object(module, "trusted_read", return_value=RUNTIME):
            old = load().Error
        with patch.object(module, "trusted_read", side_effect=OSError("PRIVATE_CONFIGURATION_SENTINEL")):
            with self.assertRaises(OSError):
                load()
        self.assertIsNone(module._SHARED_RUNTIME_ERROR)
        self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", self.capture(old("PRIVATE_CONFIGURATION_SENTINEL")))

    def test_unknown_shared_error_subclass_is_not_trusted(self):
        with patch.object(module, "trusted_read", return_value=RUNTIME):
            known = load().Error
        foreign = type("Foreign", (known,), {})
        self.assertNotIn("PRIVATE_CONFIGURATION_SENTINEL", self.capture(foreign("PRIVATE_CONFIGURATION_SENTINEL")))

    def test_help_still_exits_without_loading_runtime(self):
        with patch.object(module, "trusted_read") as read, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as done:
                module.cli(["--help"])
        self.assertEqual(done.exception.code, 0)
        read.assert_not_called()
