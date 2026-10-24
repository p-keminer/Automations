"""Offline host certificate controls; no real service, socket or trust changes."""
import contextlib
from dataclasses import replace
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


cert = module("host_cert_under_test", ROOT / "portable/python/host_cert.py")
support = module("host_cert_profile_fixture", ROOT / "common/python/platform_support.py")
PROFILE = support.Profile("kali-host", True, (), "ssh.service", "a" * 64)
PUBLIC = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"


class Runner:
    def __init__(self):
        self.active, self.enabled = "inactive", "disabled"
        self.calls, self.overrides, self.fail = [], {}, None
        self.ca_details, self.certificate_valid = "X509v3 Basic Constraints: critical\n    CA:TRUE\n", True
        self.server_valid = True
        self.credentials, self.environment_files = [["server.key", cert.KEY]], []
        self.credential_signature, self.bus_failure = "a(ss)", False
        self.display_credential, self.show_override = "[unprintable]", None
        self.unit_id, self.unit_id_signature = cert.SERVICE, "s"

    def fields(self):
        values = {"Id": cert.SERVICE, "LoadState": "loaded", "ActiveState": self.active,
                  "SubState": "running" if self.active == "active" else "dead",
                  "UnitFileState": self.enabled, "Type": "notify", "FragmentPath": cert.UNIT,
                  "DropInPaths": "", "NeedDaemonReload": "no", "DynamicUser": "yes",
                  "LoadCredential": self.display_credential, "Environment": "",
                  "RootDirectory": "", "RootImage": "", "PrivateNetwork": "no", "NetworkNamespacePath": "",
                  "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
                  "PrivateTmp": "yes", "PrivateDevices": "yes", "RestrictSUIDSGID": "yes",
                  "CapabilityBoundingSet": "",
                  "ExecStart": "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -B " + cert.PAYLOAD
                               + " --internal-serve ; ignore_errors=no ; pid=123 ; code=exited ; status=0 }"}
        values.update(self.overrides)
        return values

    def __call__(self, args):
        self.calls.append(list(args))
        if args[0] == cert.BUSCTL:
            if self.bus_failure:
                return subprocess.CompletedProcess(args, 1, "", "PRIVATE ERROR NOT FOR OUTPUT")
            if "call" in args:
                return subprocess.CompletedProcess(args, 1, "", "Call failed: Unit automations-host-cert.service not loaded.\n")
            if args[-1] == "Id":
                result = {"type": self.unit_id_signature, "data": self.unit_id}
            elif args[-1] == "LoadCredential":
                result = {"type": self.credential_signature, "data": self.credentials}
            elif args[-1] == "EnvironmentFiles":
                result = {"type": "a(sb)", "data": self.environment_files}
            else:
                raise AssertionError(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(result), "")
        if args[0] == cert.OPENSSL:
            valid = self.certificate_valid and (args[1] != "verify" or self.server_valid)
            return subprocess.CompletedProcess(args, 0 if valid else 1,
                                               self.ca_details if "basicConstraints" in args else "", "")
        if args[:2] == [cert.SYSTEMCTL, "show"]:
            output = self.show_override if self.show_override is not None else "\n".join(k + "=" + v for k, v in self.fields().items())
            return subprocess.CompletedProcess(args, 0, output, "")
        action = args[1]
        if self.fail == action:
            self.fail = None
            return subprocess.CompletedProcess(args, 1, "", "PRIVATE ERROR NOT FOR OUTPUT")
        if action in ("start", "stop"):
            self.active = "active" if action == "start" else "inactive"
        elif action in ("enable", "disable"):
            self.enabled = "enabled" if action == "enable" else "disabled"
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    def mutations(self):
        return [call[1] for call in self.calls if call[0] == cert.SYSTEMCTL and call[1] != "show"]


class HostCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root, self.uid = Path(self.temporary.name), os.geteuid()
        (self.root / "run").mkdir(mode=0o755)
        self.runner, self.profile = Runner(), PROFILE
        self.backend = cert.HostCert(self.profile, root=self.root, owner_uid=self.uid,
                                     runner=self.runner, profile_loader=lambda: self.profile)
        self.install()

    def put(self, name, data, mode=0o644):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        path.chmod(mode)
        return path

    def install(self):
        self.put(cert.UNIT, cert.UNIT_TEXT)
        self.put(cert.PAYLOAD, "#!/usr/bin/python3\n", 0o755)
        self.put(cert.SYSTEMCTL, "fixture", 0o755)
        self.put(cert.OPENSSL, "fixture", 0o755)
        self.put(cert.BUSCTL, "fixture", 0o755)
        self.put(cert.CONFIG, json.dumps({"schema_version": 1, "listen_address": "127.0.0.1", "port": 8443}))
        self.put(cert.CA, PUBLIC)
        self.put(cert.CERT, PUBLIC)
        self.put(cert.KEY, "private-key-fixture-not-a-real-key", 0o600)

    def change(self, enabled):
        with patch.object(cert.os, "geteuid", return_value=0):
            return self.backend.change(enabled)

    def test_status_is_local_reports_fingerprint_and_never_changes_trust(self):
        with patch.object(cert.socket, "socket", side_effect=AssertionError("network forbidden")):
            status = self.backend.inspect()
        self.assertTrue(status["available"])
        self.assertEqual(status["endpoint"], "https://127.0.0.1:8443/cert")
        self.assertEqual(len(status["ca_sha256"]), 64)
        self.assertEqual(self.runner.mutations(), [])
        self.assertFalse((self.root / "usr/local/share/ca-certificates").exists())

    def test_missing_optional_setup_is_unavailable_without_installing_anything(self):
        (self.root / cert.CONFIG.lstrip("/")).unlink()
        status = self.backend.inspect()
        self.assertFalse(status["available"])
        self.assertIn("not configured", status["reason"])
        self.assertEqual(self.runner.mutations(), [])

    def test_missing_dedicated_unit_never_adopts_nginx_or_another_service(self):
        (self.root / cert.UNIT.lstrip("/")).unlink()
        status = self.backend.inspect()
        self.assertFalse(status["available"])
        self.assertEqual(self.runner.calls, [])

    def test_enable_and_disable_only_own_service_and_preserve_setup_bytes(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        status, changed = self.change(True)
        self.assertTrue(changed)
        self.assertEqual((status["active_state"], status["unit_file_state"]), ("active", "enabled"))
        status, changed = self.change(False)
        self.assertTrue(changed)
        self.assertEqual((status["active_state"], status["unit_file_state"]), ("inactive", "disabled"))
        self.assertEqual(self.runner.mutations(), ["enable", "start", "stop", "disable"])
        for path, content in before.items():
            self.assertEqual((self.root / path).read_bytes(), content)
        self.assertTrue(all(call[2] == cert.SERVICE for call in self.runner.calls if call[0] == cert.SYSTEMCTL))

    def test_matching_state_is_idempotent(self):
        self.change(True)
        self.runner.calls.clear()
        _, changed = self.change(True)
        self.assertFalse(changed)
        self.assertEqual(self.runner.mutations(), [])

    def test_failed_start_restores_both_previous_states(self):
        self.runner.fail = "start"
        with self.assertRaisesRegex(cert.Error, "previous service state restored"):
            self.change(True)
        self.assertEqual((self.runner.active, self.runner.enabled), ("inactive", "disabled"))
        self.assertEqual(self.runner.mutations(), ["enable", "start", "stop", "disable"])

    def test_failed_disable_restores_active_enabled_service(self):
        self.runner.active, self.runner.enabled, self.runner.fail = "active", "enabled", "disable"
        with self.assertRaisesRegex(cert.Error, "previous service state restored"):
            self.change(False)
        self.assertEqual((self.runner.active, self.runner.enabled), ("active", "enabled"))

    def test_off_works_when_own_ca_setup_has_been_removed(self):
        self.runner.active, self.runner.enabled = "active", "enabled"
        (self.root / cert.CA.lstrip("/")).unlink()
        status, changed = self.change(False)
        self.assertTrue(changed)
        self.assertFalse(status["available"])
        self.assertEqual(self.runner.active, "inactive")
        self.assertEqual(status["active_state"], "inactive")

    def test_no_root_or_no_configured_profile_prevents_actions(self):
        with patch.object(cert.os, "geteuid", return_value=1000), self.assertRaisesRegex(cert.Error, "Root"):
            self.backend.change(True)
        self.profile = replace(PROFILE, configured=False)
        other = cert.HostCert(self.profile, root=self.root, owner_uid=self.uid, runner=self.runner,
                              profile_loader=lambda: self.profile)
        with patch.object(cert.os, "geteuid", return_value=0), self.assertRaisesRegex(cert.Error, "explicit"):
            other.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_profile_identity_reload_rejects_concurrent_change_before_mutation(self):
        self.profile = replace(PROFILE, identity="b" * 64)
        with self.assertRaisesRegex(cert.Error, "profile changed"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_symlink_and_group_writable_setup_are_rejected(self):
        path = self.root / cert.CONFIG.lstrip("/")
        path.chmod(0o664)
        with self.assertRaisesRegex(cert.Error, "root-protected"):
            self.backend.inspect()
        path.chmod(0o644)
        path.unlink()
        path.symlink_to(self.root / cert.CA.lstrip("/"))
        with self.assertRaisesRegex(cert.Error, "root-protected"):
            self.backend.inspect()

    def test_public_or_hardlinked_private_key_is_rejected(self):
        path = self.root / cert.KEY.lstrip("/")
        path.chmod(0o644)
        with self.assertRaisesRegex(cert.Error, "0600"):
            self.backend.inspect()
        path.chmod(0o600)
        os.link(path, self.root / "extra-key-link")
        with self.assertRaisesRegex(cert.Error, "Invalid"):
            self.backend.inspect()

    def test_private_or_extra_data_is_never_served_as_public_ca(self):
        self.put(cert.CA, PUBLIC + b"SECRET EXTRA DATA")
        with self.assertRaisesRegex(cert.Error, "public CA"):
            self.backend.inspect()

    def test_non_ca_or_expired_certificates_prevent_start(self):
        self.runner.ca_details = "X509v3 Basic Constraints:\n    CA:FALSE\n"
        with self.assertRaisesRegex(cert.Error, "CA certificate"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])
        self.runner.certificate_valid = False
        with self.assertRaises(cert.Error):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_server_chain_or_ip_mismatch_prevents_start_with_own_ca_only(self):
        self.runner.server_valid = False
        with self.assertRaises(cert.Error):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])
        verification = [call for call in self.runner.calls if call[:2] == [cert.OPENSSL, "verify"]][0]
        self.assertIn("-no-CApath", verification)
        self.assertIn("-no-CAstore", verification)
        self.assertEqual(verification[verification.index("-verify_ip") + 1], "127.0.0.1")
        self.assertEqual(verification[verification.index("-CAfile") + 1], str(self.root / cert.CA.lstrip("/")))

    def test_unknown_unit_dropin_environment_or_stale_loaded_unit_is_rejected(self):
        for key, value in (("DropInPaths", "/etc/evil.conf"), ("NeedDaemonReload", "yes"),
                           ("Environment", "PYTHONPATH=/tmp"), ("DynamicUser", "no"),
                           ("CapabilityBoundingSet", "cap_net_admin")):
            with self.subTest(key=key):
                self.runner.overrides = {key: value}
                with self.assertRaisesRegex(cert.Error, "loaded host"):
                    self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_native_unprintable_display_and_omitted_environment_files_use_typed_properties(self):
        self.assertEqual(self.runner.fields()["LoadCredential"], "[unprintable]")
        self.assertNotIn("EnvironmentFiles", self.runner.fields())
        (self.root / cert.CONFIG.lstrip("/")).unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = cert.main(["--status"], profile_loader=lambda: PROFILE,
                               backend_factory=lambda _profile, **_kw: self.backend)
        self.assertEqual(result, 3)
        properties = [call[-1] for call in self.runner.calls if call[0] == cert.BUSCTL and "get-property" in call]
        self.assertEqual(properties, ["Id", "LoadCredential", "EnvironmentFiles"])
        self.assertEqual(self.runner.mutations(), [])

    def test_inactive_unit_gc_does_not_require_a_manager_lookup_or_service_start(self):
        self.assertEqual(self.runner.active, "inactive")
        self.assertTrue(self.backend.inspect()["available"])
        reads = [call for call in self.runner.calls if call[0] == cert.BUSCTL]
        self.assertEqual(len(reads), 3)
        for call in reads:
            self.assertIn("get-property", call)
            self.assertIn(cert.BUS_UNIT_OBJECT, call)
            self.assertNotIn("call", call)
            self.assertNotIn("GetUnit", call)
            self.assertNotIn("LoadUnit", call)
        self.assertEqual(self.runner.mutations(), [])

    def test_fixed_unit_object_requires_its_exact_typed_identity(self):
        for value, signature in (("foreign.service", "s"), ([cert.SERVICE], "s"), (cert.SERVICE, "o")):
            with self.subTest(value=value, signature=signature):
                self.runner.unit_id, self.runner.unit_id_signature = value, signature
                with self.assertRaises(cert.Error):
                    self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_unprintable_display_alone_does_not_accept_an_unknown_or_extra_credential(self):
        for credentials in ([], [["server.key", "/tmp/foreign.key"]],
                            [["server.key", cert.KEY], ["extra", cert.CA]],
                            [["server.key", cert.KEY], ["server.key", cert.KEY]],
                            "[unprintable]", {"server.key": cert.KEY}):
            with self.subTest(credentials=credentials):
                self.runner.credentials = credentials
                with self.assertRaisesRegex(cert.Error, "credential mappings"):
                    self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_structured_signature_and_hidden_environment_files_are_not_relaxed(self):
        self.runner.credential_signature = "s"
        with self.assertRaisesRegex(cert.Error, "signature"):
            self.change(True)
        self.runner.credential_signature = "a(ss)"
        self.runner.environment_files = [["/tmp/foreign.env", False]]
        with self.assertRaisesRegex(cert.Error, "environment files"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_dbus_read_failure_is_an_error_before_mutation(self):
        self.runner.bus_failure = True
        with self.assertRaisesRegex(cert.Error, "command failed"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_extra_execstart_is_rejected(self):
        self.runner.overrides["ExecStart"] = self.runner.fields()["ExecStart"] + " ; { path=/bin/true ; }"
        with self.assertRaisesRegex(cert.Error, "Unexpected"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_lock_contention_does_not_enter_operation(self):
        with self.backend.lock(), self.assertRaisesRegex(cert.Error, "Another host"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_changed_certificate_after_read_is_not_started(self):
        self.backend.configuration()
        self.put(cert.CA, PUBLIC.replace(b"QUJD", b"REVG"))
        with self.assertRaisesRegex(cert.Error, "setup changed"):
            self.change(True)
        self.assertEqual(self.runner.mutations(), [])

    def test_help_never_loads_profile_and_unknown_worker_options_are_not_accepted(self):
        with patch.object(cert, "load_profile", side_effect=AssertionError("must not load")), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                cert.main(["--help"])
            self.assertEqual(result.exception.code, 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cert.main(["--internal-serve", "--on"])

    def test_cli_missing_setup_exit_three_and_no_key_or_stderr_disclosure(self):
        (self.root / cert.CA.lstrip("/")).unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cert.main(["--status"], profile_loader=lambda: PROFILE,
                             backend_factory=lambda _profile, **_kw: self.backend)
        self.assertEqual(code, 3)
        self.assertIn("unavailable", output.getvalue())
        self.assertNotIn("private-key-fixture", output.getvalue())


class ConfigAndDownloadTests(unittest.TestCase):
    def test_packaged_service_is_exactly_the_supported_definition(self):
        path = ROOT / "portable/components/cert-control/files/automations-host-cert.service"
        self.assertEqual(path.read_bytes(), cert.UNIT_TEXT.encode("utf-8"))

    def test_config_requires_explicit_numeric_address_and_unprivileged_port(self):
        base = {"schema_version": 1, "listen_address": "127.0.0.1", "port": 8443}
        for change in ({"listen_address": "0.0.0.0"}, {"listen_address": "localhost"},
                       {"listen_address": "ff02::1"}, {"listen_address": "fe80::1%eth0"},
                       {"listen_address": "::ffff:0.0.0.0"}, {"listen_address": "255.255.255.255"},
                       {"port": True}, {"port": 443}, {"unknown": "ignored?"}, {"schema_version": True}):
            with self.subTest(change=change), self.assertRaises(cert.Error):
                cert.parse_config(json.dumps({**base, **change}).encode())
        self.assertEqual(cert.parse_config(json.dumps({**base, "listen_address": "::1"}).encode())["listen_address"], "::1")
        self.assertEqual(cert.parse_config(json.dumps({**base, "listen_address": "192.0.2.1"}).encode())["port"], 8443)

    def test_duplicate_config_field_is_rejected(self):
        with self.assertRaisesRegex(cert.Error, "Duplicate"):
            cert.parse_config(b'{"schema_version":1,"listen_address":"127.0.0.1","port":8443,"port":9443}')

    def request(self, path, method="GET"):
        handler = object.__new__(cert.handler_for(PUBLIC))
        handler.path, handler.wfile, handler.headers_seen = path, io.BytesIO(), []
        handler.send_response = lambda value: handler.headers_seen.append(("status", value))
        handler.send_header = lambda key, value: handler.headers_seen.append((key, value))
        handler.end_headers = lambda: None
        handler.send_error = lambda value: handler.headers_seen.append(("error", value))
        getattr(handler, "do_" + method)()
        return handler

    def test_get_and_head_only_offer_public_certificate_bytes(self):
        for path in ("/cert", "/automations-ca.crt"):
            result = self.request(path)
            self.assertEqual(result.wfile.getvalue(), PUBLIC)
            self.assertIn(("status", 200), result.headers_seen)
            self.assertIn(("Content-Length", str(len(PUBLIC))), result.headers_seen)
            self.assertEqual(self.request(path, "HEAD").wfile.getvalue(), b"")

    def test_unknown_queries_traversal_and_private_key_paths_are_404(self):
        for path in ("/", "/server.key", "/../server.key", "/cert?file=server.key", "/%63ert", "/etc/passwd"):
            with self.subTest(path=path):
                result = self.request(path)
                self.assertIn(("error", 404), result.headers_seen)
                self.assertEqual(result.wfile.getvalue(), b"")

    def test_worker_rejects_direct_root_invocation_before_any_socket(self):
        with patch.object(cert.os, "geteuid", return_value=0), \
                patch.object(cert.socket, "socket", side_effect=AssertionError("network forbidden")), \
                self.assertRaisesRegex(cert.Error, "unprivileged"):
            cert.serve(object())

    def test_worker_rejects_unrelated_cgroup_before_configuration_or_socket(self):
        with patch.object(cert.os, "geteuid", return_value=65520), \
                patch.dict(cert.os.environ, {"CREDENTIALS_DIRECTORY": cert.CREDENTIALS}), \
                patch.object(cert.Path, "read_text", return_value="0::/user.slice/not-our.service\n"), \
                patch.object(cert.socket, "socket", side_effect=AssertionError("network forbidden")), \
                self.assertRaisesRegex(cert.Error, "fixed system service"):
            cert.serve(object())

    def test_numeric_bind_does_not_perform_reverse_dns(self):
        config = {"listen_address": "192.0.2.1", "port": 8443}
        server_class = cert.server_type(config, object())
        server = object.__new__(server_class)
        server.server_address = ("192.0.2.1", 8443)
        server.socket = Mock()
        server.socket.getsockname.return_value = server.server_address
        with patch.object(cert.socket, "getfqdn", side_effect=AssertionError("DNS forbidden")):
            server.server_bind()
        self.assertEqual(server.server_name, "192.0.2.1")
        server.socket.bind.assert_called_once_with(("192.0.2.1", 8443))

    def test_tls_accept_is_bounded_and_failed_handshake_closes_owned_socket(self):
        context, connection, secured = Mock(), Mock(), Mock()
        server = object.__new__(cert.server_type({"listen_address": "::1"}, context))
        server.socket = Mock()
        server.socket.accept.return_value = (connection, ("::1", 12345))
        context.wrap_socket.return_value = secured
        self.assertEqual(server.get_request(), (secured, ("::1", 12345)))
        connection.settimeout.assert_called_once_with(5)
        context.wrap_socket.assert_called_once_with(connection, server_side=True)
        context.wrap_socket.side_effect = cert.ssl.SSLError("handshake rejected")
        with self.assertRaises(cert.ssl.SSLError):
            server.get_request()
        connection.close.assert_called_once_with()

    def test_runner_is_bounded_has_no_shell_and_drops_caller_environment(self):
        with patch.object(cert.subprocess, "run", return_value=object()) as process:
            cert.run([cert.SYSTEMCTL, "show", cert.SERVICE])
        kwargs = process.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 45)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(set(kwargs["env"]), {"PATH", "LC_ALL"})


class CredentialPrivacyTests(unittest.TestCase):
    UID = 64936

    def acl(self, permission=4, *, uid=UID, version=2, entries=None):
        entries = entries if entries is not None else [
            (1, permission, 0xffffffff), (2, permission, uid),
            (4, 0, 0xffffffff), (16, permission, 0xffffffff), (32, 0, 0xffffffff)]
        return struct.pack("<I", version) + b"".join(struct.pack("<HHI", *entry) for entry in entries)

    def info(self, *, directory=False, mode=None, uid=0, gid=0, **changes):
        value = dict(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)
                            | (mode if mode is not None else (0o550 if directory else 0o440)),
                     st_uid=uid, st_gid=gid, st_nlink=2 if directory else 1,
                     st_dev=os.makedev(0, 51), st_size=60 if directory else 1704)
        value.update(changes)
        return SimpleNamespace(**value)

    def mount(self):
        return ("419 418 0:51 / " + cert.CREDENTIALS
                + " ro,nosuid,nodev,noexec,relatime,nosymfollow shared:315 master:300"
                  " - tmpfs none ro,size=1024k,nr_inodes=1024,mode=700,inode64,noswap\n")

    def test_native_systemd_acl_mask_is_not_owning_group_access(self):
        cert.credential_access(self.info(), self.acl(), self.UID)
        cert.credential_access(self.info(directory=True), self.acl(5), self.UID, directory=True)

    def test_systemd_non_acl_fallback_requires_worker_owner_and_read_only_private_mode(self):
        cert.credential_access(self.info(mode=0o400, uid=self.UID), None, self.UID)
        cert.credential_access(self.info(directory=True, mode=0o500, uid=self.UID),
                               None, self.UID, directory=True)
        for mode, owner in ((0o440, self.UID), (0o444, self.UID), (0o600, self.UID), (0o400, 0)):
            with self.subTest(mode=mode, owner=owner), self.assertRaises(cert.Error):
                cert.credential_access(self.info(mode=mode, uid=owner), None, self.UID)

    def test_extra_principals_group_world_write_or_unknown_acl_are_rejected(self):
        ordinary = [(1, 4, 0xffffffff), (2, 4, self.UID), (4, 0, 0xffffffff),
                    (16, 4, 0xffffffff), (32, 0, 0xffffffff)]
        invalid = [self.acl(uid=self.UID + 1), self.acl(version=3), self.acl()[:-1],
                   self.acl(entries=ordinary + [(2, 4, self.UID + 1)]),
                   self.acl(entries=ordinary + [(8, 4, 1000)])]
        for index, value in ((0, (1, 6, 0xffffffff)), (1, (2, 6, self.UID)),
                             (1, (8, 4, self.UID)), (2, (4, 4, 0xffffffff)),
                             (3, (16, 6, 0xffffffff)), (4, (32, 4, 0xffffffff)),
                             (4, ordinary[0])):
            changed = list(ordinary)
            changed[index] = value
            invalid.append(self.acl(entries=changed))
        for raw in invalid:
            with self.subTest(acl=raw.hex()), self.assertRaises(cert.Error):
                cert.credential_access(self.info(), raw, self.UID)
        for info in (self.info(uid=self.UID), self.info(gid=1000), self.info(mode=0o444),
                     self.info(st_mode=stat.S_IFLNK | 0o440)):
            with self.subTest(info=info), self.assertRaises(cert.Error):
                cert.credential_access(info, self.acl(), self.UID)

    def test_only_exact_protected_memory_mount_and_device_are_accepted(self):
        cert.credential_mount(self.mount(), self.info(directory=True))
        for content in (self.mount().replace(" ro,nosuid", " rw,nosuid"),
                        self.mount().replace(",noexec", ""),
                        self.mount().replace(" - tmpfs ", " - ext4 "),
                        self.mount().replace("0:51", "0:52"),
                        self.mount().replace(" / ", " /subdirectory "),
                        self.mount().replace(cert.CREDENTIALS, cert.CREDENTIALS + "-other"),
                        self.mount() * 2, self.mount().replace(" - tmpfs none ro,", " - tmpfs none rw,")):
            with self.subTest(content=content), self.assertRaises(cert.Error):
                cert.credential_mount(content, self.info(directory=True))

    def inspect(self, *, default_acl=None, key_changes=None, mount_flags=os.ST_RDONLY):
        def metadata(path):
            if str(path) == cert.CREDENTIALS:
                return self.info(directory=True)
            if str(path) == cert.CREDENTIALS + "/server.key":
                return self.info(**(key_changes or {}))
            return self.info(directory=True, mode=0o755)

        def acl(path, *, default=False):
            return default_acl if default else self.acl(5 if str(path) == cert.CREDENTIALS else 4)

        with patch.object(cert.Path, "lstat", metadata), \
                patch.object(cert.Path, "read_text", return_value=self.mount()), \
                patch.object(cert.Path, "read_bytes", side_effect=AssertionError("must not read private key")), \
                patch.object(cert, "credential_acl", side_effect=acl), \
                patch.object(cert.os, "geteuid", return_value=self.UID), \
                patch.object(cert.os, "statvfs", return_value=SimpleNamespace(f_flag=mount_flags)):
            return cert.credential_file()

    def test_worker_credential_inspection_checks_metadata_without_reading_key(self):
        self.assertEqual(str(self.inspect()), cert.CREDENTIALS + "/server.key")

    def test_default_acl_hardlinks_overmount_empty_key_and_writable_mount_are_rejected(self):
        for options in ({"default_acl": self.acl(5)}, {"key_changes": {"st_nlink": 2}},
                        {"key_changes": {"st_dev": os.makedev(0, 52)}},
                        {"key_changes": {"st_size": 0}}, {"mount_flags": 0}):
            with self.subTest(options=options), self.assertRaises(cert.Error):
                self.inspect(**options)

    def test_acl_read_failure_is_not_treated_as_no_acl(self):
        for error in (errno.EACCES, errno.EIO):
            with self.subTest(error=error), \
                    patch.object(cert.os, "getxattr", side_effect=OSError(error, "fixture")), \
                    self.assertRaisesRegex(cert.Error, "inspect.*ACL"):
                cert.credential_acl(Path(cert.CREDENTIALS))
        with patch.object(cert.os, "getxattr", side_effect=OSError(errno.ENODATA, "fixture")):
            self.assertIsNone(cert.credential_acl(Path(cert.CREDENTIALS)))


if __name__ == "__main__":
    unittest.main()
