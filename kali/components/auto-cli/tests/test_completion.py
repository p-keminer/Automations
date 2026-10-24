"""Completion grammar and no-execution regressions for the shared reader."""

import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "auto_completion", ROOT / "python/auto_completion.py"
)
completion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(completion)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.commands = self.root / "commands"
        self.data = self.root / "data"
        self.sysnet = self.root / "sysnet"
        self.support = self.root / "support"
        self.state = self.root / "state.json"
        self.boot_id = self.root / "boot-id"
        self.boot_id.write_text(
            "2590d118-5f40-4d19-9437-2c378a281ab0\n", encoding="utf-8"
        )
        for directory in (self.commands, self.data, self.sysnet, self.support):
            directory.mkdir()
        for name in ("ctrl0", "eth0", "lo", "wlan0", "wlan1"):
            (self.sysnet / name).mkdir()
        self.phys = self.root / "phys"
        self.phys.mkdir()
        for name, phy in (("ctrl0", "phy0"), ("wlan0", "phy1"), ("wlan1", "phy2")):
            physical = self.phys / phy
            physical.mkdir()
            (self.sysnet / name / "phy80211").symlink_to(
                physical, target_is_directory=True
            )
        self.command("cert")
        self.command("share")
        self.command("wifi")
        self.command("tor")
        self.options("cert", "--on", "--off", "--status", "--help")
        self.options(
            "share", "--wifi", "--lan", "--off", "--status",
            "--help", "--to", "--from", "ap"
        )
        self.options(
            "wifi", "--off", "--monitor", "--managed", "--status",
            "--interface", "--help", "--autoconnect-on", "--autoconnect-off"
        )
        self.options(
            "tor", "--on", "--off", "--status", "--rotate",
            "--rotate-every", "--rotation-off", "--check", "--ip", "--help"
        )

    def command(self, name, text="#!/bin/sh\nexit 0\n", mode=0o755):
        path = self.commands / name
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def options(self, name, *values):
        path = self.data / name
        path.write_text("\n".join(values) + "\n", encoding="utf-8")
        return path

    def hotspot(self):
        path = self.support / "hotspot.py"
        path.write_text("# Installed hotspot support fixture.\n", encoding="utf-8")
        path.chmod(0o644)
        self.options("share-ap", "--interface", "--off", "--status", "--help")
        return path

    def suggest(self, *words):
        return completion.candidates(
            list(words), len(words) - 1,
            commands=self.commands, data=self.data,
            sysnet=self.sysnet, support=self.support,
            state=self.state, boot_id=self.boot_id,
        )

    def active_ap(self):
        veth = self.sysnet / "autoap0"
        veth.mkdir(exist_ok=True)
        (veth / "ifindex").write_text("77\n", encoding="utf-8")
        value = {
            "version": 1, "phase": "active",
            "boot_id": self.boot_id.read_text().strip(),
            "veth_index": 77, "adapter": ["wlan0"],
        }
        self.state.write_text(json.dumps(value), encoding="utf-8")
        return value

    def bash_suggest(self, line, words, cword, *, point=None,
                     library=True, remove_breaks=False):
        helpers = Path("/usr/share/bash-completion/bash_completion")
        if library and not helpers.is_file():
            self.skipTest("Native bash-completion helpers are not installed.")
        reader = self.root / "reader.py"
        source = (ROOT / "python/auto_completion.py").read_text()
        for installed, fixture in (
            ("/usr/local/libexec/automations", self.commands),
            ("/usr/local/share/automations/completions", self.data),
            ("/sys/class/net", self.sysnet),
            ("/usr/local/libexec/automations-support", self.support),
            ("/run/automations-hotspot/state.json", self.state),
            ("/proc/sys/kernel/random/boot_id", self.boot_id),
        ):
            expression = "Path(" + repr(installed) + ")"
            self.assertIn(expression, source)
            source = source.replace(expression, "Path(" + repr(str(fixture)) + ")")
        reader.write_text(source, encoding="utf-8")
        wrapper = self.root / "completion.sh"
        wrapper.write_text(
            (ROOT / "shell/bash/auto-completion.sh").read_text().replace(
                "/usr/local/libexec/automations-support/completion.py", str(reader)
            ),
            encoding="utf-8",
        )
        setup = (
            "source " + shlex.quote(str(helpers)) + "\n" if library else ""
        )
        if remove_breaks:
            setup += "COMP_WORDBREAKS=${COMP_WORDBREAKS//=/}\n"
            setup += "COMP_WORDBREAKS=${COMP_WORDBREAKS//:/}\n"
        script = (
            setup
            + "source " + shlex.quote(str(wrapper)) + "\n"
            + "COMP_LINE=" + shlex.quote(line) + "\n"
            + "COMP_POINT=" + str(len(line) if point is None else point) + "\n"
            + "COMP_WORDS=(" + " ".join(shlex.quote(word) for word in words) + ")\n"
            + "COMP_CWORD=" + str(cword) + "\n"
            + "before=$COMP_WORDBREAKS\n"
            + "_auto_complete\n"
            + "[[ $COMP_WORDBREAKS == \"$before\" ]] || exit 91\n"
            + "if (( ${#COMPREPLY[@]} )); then printf '%s\\0' \"${COMPREPLY[@]}\"; fi\n"
        )
        result = subprocess.run(
            ["bash", "--noprofile", "--norc"], input=script, text=True,
            capture_output=True, cwd=self.root,
            env={
                "PATH": "/usr/bin:/bin", "HOME": str(self.root),
                "LC_ALL": "C", "BASH_ENV": "/dev/null",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout.rstrip("\0").split("\0") if result.stdout else []

    def test_command_prefix_lists_installed_executables_only(self):
        self.command("shallow", mode=0o644)
        self.command("share.invalid")
        (self.commands / "shared-directory").mkdir()
        (self.commands / "shared-link").symlink_to(self.commands / "share")
        self.assertEqual(self.suggest("auto", "sha"), ["share"])

    def test_root_help_and_installed_command_discovery(self):
        found = set(self.suggest("auto", ""))
        self.assertTrue({"--help", "cert", "share", "wifi", "tor"} <= found)
        self.assertNotIn("share-ap", found)
        self.assertEqual(self.suggest("auto", "--he"), ["--help"])

    def test_option_prefix_does_not_include_files(self):
        (self.root / "--ordinary-file").write_text("fixture", encoding="utf-8")
        self.assertEqual(
            set(self.suggest("auto", "cert", "--o")), {"--on", "--off"}
        )
        self.assertNotIn("--ordinary-file", self.suggest("auto", "cert", ""))

    def test_missing_or_nonexecutable_command_has_no_options(self):
        self.options("missing", "--off")
        self.command("disabled", mode=0o644)
        self.options("disabled", "--off")
        self.assertEqual(self.suggest("auto", "missing", "--"), [])
        self.assertEqual(self.suggest("auto", "disabled", "--"), [])

    def test_symlink_command_is_not_a_completion_target(self):
        (self.commands / "linked").symlink_to(self.commands / "cert")
        self.options("linked", "--on")
        self.assertEqual(self.suggest("auto", "linked", "--"), [])
        self.assertNotIn("linked", self.suggest("auto", ""))

    def test_missing_or_symlink_option_data_is_not_read(self):
        (self.data / "cert").unlink()
        self.assertEqual(self.suggest("auto", "cert", "--"), [])
        outside = self.root / "foreign-options"
        outside.write_text("--foreign\n", encoding="utf-8")
        (self.data / "cert").symlink_to(outside)
        self.assertEqual(self.suggest("auto", "cert", "--"), [])

    def test_payload_and_malicious_completion_data_are_never_executed(self):
        marker = self.root / "must-not-exist"
        self.command("cert", "#!/bin/sh\ntouch " + str(marker) + "\n")
        self.options(
            "cert", "--on", "--off", "$(touch " + str(marker) + ")",
            "; touch " + str(marker), "--bad;touch", "../foreign", "ordinary"
        )
        self.assertEqual(
            set(self.suggest("auto", "cert", "")), {"--on", "--off"}
        )
        self.assertFalse(marker.exists())

    def test_path_like_command_names_do_not_read_foreign_data(self):
        outside = self.root / "foreign"
        outside.write_text("--foreign\n", encoding="utf-8")
        for command in ("../foreign", "/bin/sh", "cert;echo"):
            with self.subTest(command=command):
                self.assertEqual(self.suggest("auto", command, ""), [])

    def test_share_ap_requires_both_support_and_own_option_data(self):
        self.assertNotIn("ap", self.suggest("auto", "share", ""))
        helper = self.hotspot()
        self.assertIn("ap", self.suggest("auto", "share", ""))
        (self.data / "share-ap").unlink()
        self.assertNotIn("ap", self.suggest("auto", "share", ""))
        self.options("share-ap", "--off")
        helper.unlink()
        self.assertNotIn("ap", self.suggest("auto", "share", ""))

    def test_symlink_hotspot_support_does_not_offer_ap(self):
        helper = self.hotspot()
        helper.unlink()
        foreign = self.root / "foreign-hotspot.py"
        foreign.write_text("# fixture\n", encoding="utf-8")
        helper.symlink_to(foreign)
        self.assertNotIn("ap", self.suggest("auto", "share", ""))
        self.assertEqual(self.suggest("auto", "share", "ap", "--"), [])

    def test_nested_ap_uses_hotspot_options_not_share_options(self):
        self.hotspot()
        self.assertEqual(
            set(self.suggest("auto", "share", "ap", "--")),
            {"--interface", "--off", "--status", "--help"},
        )
        self.assertEqual(self.suggest("auto", "share", "a"), ["ap"])
        self.assertEqual(
            self.suggest("auto", "share", "ap", "--in"), ["--interface"]
        )
        self.assertNotIn("--to", self.suggest("auto", "share", "ap", ""))
        self.assertNotIn("--from", self.suggest("auto", "share", "ap", ""))

    def test_symlink_nested_option_data_does_not_offer_ap(self):
        self.hotspot()
        (self.data / "share-ap").unlink()
        (self.data / "share-ap").symlink_to(self.data / "cert")
        self.assertNotIn("ap", self.suggest("auto", "share", ""))
        self.assertEqual(self.suggest("auto", "share", "ap", "--"), [])

    def test_interface_value_contexts_return_names_instead_of_options(self):
        self.hotspot()
        contexts = (
            ("auto", "wifi", "--interface", "w"),
            ("auto", "share", "--wifi", "--to", "w"),
            ("auto", "share", "--wifi", "--interface", "w"),
            ("auto", "share", "ap", "--interface", "w"),
        )
        for words in contexts:
            with self.subTest(words=words):
                self.assertEqual(set(self.suggest(*words)), {"wlan0", "wlan1"})

    def test_from_value_preserves_existing_comma_selections(self):
        self.active_ap()
        # The guest radio lives in its AP namespace, not the host's sysfs view.
        (self.sysnet / "wlan0/phy80211").unlink()
        (self.sysnet / "wlan0").rmdir()
        self.assertEqual(
            set(self.suggest("auto", "share", "--wifi", "--from", "ctrl0,w")),
            {"ctrl0,wlan0"},
        )
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--from", "ct"), ["ctrl0"]
        )

    def test_from_without_confirmed_ap_offers_only_control_source(self):
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--from", ""), ["ctrl0"]
        )
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--from", "ctrl0,"), []
        )

    def test_from_rejects_stale_or_invalid_ap_metadata(self):
        valid = self.active_ap()
        for change in (
            {"boot_id": "older-boot"},
            {"veth_index": 78},
            {"phase": "starting"},
            {"version": 2},
            {"adapter": ["ctrl0"]},
            {"adapter": ["autoap0"]},
            {"adapter": ["lo"]},
            {"adapter": ["wlan0;echo"]},
            {"adapter": None},
        ):
            with self.subTest(change=change):
                self.state.write_text(json.dumps({**valid, **change}), encoding="utf-8")
                self.assertEqual(
                    self.suggest("auto", "share", "--wifi", "--from", ""),
                    ["ctrl0"],
                )
        self.state.write_text("{not-json", encoding="utf-8")
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--from", ""), ["ctrl0"]
        )

    def test_from_does_not_trust_symlink_ap_state(self):
        self.active_ap()
        foreign = self.root / "foreign-state.json"
        foreign.write_text(self.state.read_text(), encoding="utf-8")
        self.state.unlink()
        self.state.symlink_to(foreign)
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--from", ""), ["ctrl0"]
        )

    def test_wireless_values_exclude_control_radio_loopback_and_ethernet(self):
        sibling = self.sysnet / "ctrl-sibling"
        sibling.mkdir()
        (sibling / "phy80211").symlink_to(
            self.phys / "phy0", target_is_directory=True
        )
        self.hotspot()
        for words in (
            ("auto", "wifi", "--interface", ""),
            ("auto", "share", "--wifi", "--to", ""),
            ("auto", "share", "ap", "--interface", ""),
        ):
            with self.subTest(words=words):
                self.assertEqual(set(self.suggest(*words)), {"wlan0", "wlan1"})

    def test_lan_values_exclude_wireless_control_and_loopback_interfaces(self):
        self.assertEqual(
            self.suggest("auto", "share", "--lan", "--to", ""), ["eth0"]
        )

    def test_interval_value_context_and_prefix_filtering(self):
        self.assertEqual(
            set(self.suggest("auto", "tor", "--rotate-every", "")),
            {"30s", "1m", "2m", "5m", "1h", "24h"},
        )
        self.assertEqual(
            set(self.suggest("auto", "tor", "--rotate-every", "2")),
            {"2m", "24h"},
        )

    def test_ip_and_free_ssid_arguments_do_not_offer_files(self):
        self.hotspot()
        for words in (
            ("auto", "tor", "--check", "--ip", ""),
            ("auto", "tor", "--check", "--ip", "1"),
            ("auto", "wifi", "My"),
            ("auto", "share", "ap", "My"),
        ):
            with self.subTest(words=words):
                self.assertEqual(self.suggest(*words), [])

    def test_options_resume_after_a_completed_option_value(self):
        self.assertEqual(
            self.suggest("auto", "share", "--wifi", "--to", "wlan1", "--s"),
            ["--status"],
        )

    def test_option_terminator_disables_option_suggestions(self):
        self.hotspot()
        for words in (
            ("auto", "wifi", "--", "--"),
            ("auto", "share", "--", "--"),
            ("auto", "share", "ap", "--", "--"),
        ):
            with self.subTest(words=words):
                self.assertEqual(self.suggest(*words), [])

    def test_argument_value_after_terminator_is_not_treated_as_an_option(self):
        self.assertEqual(
            self.suggest("auto", "wifi", "--", "--interface", "w"), []
        )

    def test_all_current_command_metadata_completes_without_execution(self):
        commands = set()
        for identifier in (
            "ap-control", "cert-control", "fan-control", "share-control",
            "ssh-control", "tor-control", "wifi-control",
        ):
            manifest = json.loads(
                (ROOT / "components" / identifier / "component.json").read_text()
            )
            mappings = manifest["files"]
            command = next(
                Path(item["destination"]).name for item in mappings
                if item["destination"].startswith("usr/local/libexec/automations/")
            )
            metadata = next(
                item for item in mappings
                if item["destination"] ==
                "usr/local/share/automations/completions/" + command
            )
            source = (ROOT / metadata["source"]).read_text()
            self.command(command)
            (self.data / command).write_text(source, encoding="utf-8")
            commands.add(command)
            expected = {line for line in source.splitlines() if line.startswith("--")}
            with self.subTest(command=command):
                self.assertEqual(set(self.suggest("auto", command, "--")), expected)
        self.assertEqual(commands, {"ap", "cert", "fan", "share", "ssh", "tor", "wifi"})

    def test_bash_raw_equals_value_uses_native_word_reassembly(self):
        self.assertEqual(
            set(self.bash_suggest(
                "auto share --wifi --to=wl",
                ["auto", "share", "--wifi", "--to", "=", "wl"], 5,
            )),
            {"wlan0", "wlan1"},
        )

    def test_bash_raw_empty_equals_value_has_no_duplicated_option(self):
        for words, index in (
            (["auto", "share", "--wifi", "--to", "="], 4),
            (["auto", "share", "--wifi", "--to", "=", ""], 5),
        ):
            with self.subTest(words=words):
                self.assertEqual(
                    set(self.bash_suggest(
                        "auto share --wifi --to=", words, index
                    )),
                    {"wlan0", "wlan1"},
                )

    def test_bash_raw_colon_value_strips_only_readline_prefix(self):
        interface = self.sysnet / "wlan0:1"
        interface.mkdir()
        (interface / "phy80211").symlink_to(
            self.phys / "phy1", target_is_directory=True
        )
        self.assertEqual(
            self.bash_suggest(
                "auto wifi --interface wlan0:",
                ["auto", "wifi", "--interface", "wlan0", ":"], 4,
            ),
            ["1"],
        )

    def test_bash_raw_equals_and_colon_use_the_last_active_break(self):
        interface = self.sysnet / "wlan0:1"
        interface.mkdir()
        (interface / "phy80211").symlink_to(
            self.phys / "phy1", target_is_directory=True
        )
        self.assertEqual(
            self.bash_suggest(
                "auto wifi --interface=wlan0:",
                ["auto", "wifi", "--interface", "=", "wlan0", ":"], 5,
            ),
            ["1"],
        )

    def test_bash_without_equals_wordbreak_keeps_the_whole_candidate(self):
        self.assertEqual(
            set(self.bash_suggest(
                "auto share --wifi --to=wl",
                ["auto", "share", "--wifi", "--to=wl"], 3,
                remove_breaks=True,
            )),
            {"--to=wlan0", "--to=wlan1"},
        )

    def test_bash_native_helper_obeys_the_cursor_before_a_word_suffix(self):
        self.assertEqual(
            self.bash_suggest(
                "auto share --staZZ", ["auto", "share", "--staZZ"], 2,
                point=len("auto share --sta"),
            ),
            ["--status"],
        )

    def test_bash_direct_source_without_completion_helpers_still_works(self):
        self.assertEqual(
            set(self.bash_suggest(
                "auto cert --o", ["auto", "cert", "--o"], 2, library=False
            )),
            {"--on", "--off"},
        )


if __name__ == "__main__":
    unittest.main()
