import copy
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("component_tools", Path(__file__).resolve().parents[1] / "tools/components.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / "components/demo"
        (self.folder / "tests").mkdir(parents=True)
        (self.root / "python").mkdir(parents=True)
        (self.root / "python/demo.py").write_text("print('demo')\n")
        (self.folder / "README.md").write_text("Demo\n")
        (self.folder / "tests/test_demo.py").write_text("import unittest\n")
        self.data = {"schema_version": 1, "id": "demo", "version": "0.1.0", "name": "Demo", "description": "Example",
                     "default_enabled": False, "targets": {"distributions": ["kali"], "architectures": ["arm64"]},
                     "packages": [], "files": [{"source": "python/demo.py", "destination": "usr/local/bin/demo", "mode": "0755"}]}
        self.add_docs(self.data)
        self.save()

    def add_docs(self, data, category="python"):
        identifier = data["id"]
        for language in ("de", "en"):
            source = f"{category}/docs/{language}/{identifier}.txt"
            target = self.root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("Short component instructions.\n")
            data["files"].append({"source": source, "destination": f"usr/local/share/automations/help/docs/{language}/{identifier}.txt", "mode": "0644"})

    def save(self):
        (self.folder / "component.json").write_text(json.dumps(self.data))

    def invalid(self):
        self.save()
        with self.assertRaises(ValueError):
            tool.load_components(self.root)

    def test_valid_catalog(self):
        self.assertEqual(tool.load_components(self.root), {"demo": self.data})

    def test_tool_root_is_the_kali_workspace(self):
        self.assertEqual(tool.ROOT, Path(__file__).resolve().parents[1])

    def test_legacy_and_foreign_sources_are_rejected_locally(self):
        for source in (
            "kali/python/demo.py", "kali/bash/demo.sh",
            "shell/fish/demo.fish", "components/other/files/demo.py",
        ):
            with self.subTest(source=source):
                target = self.root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("fixture\n")
                self.data["files"][0]["source"] = source
                self.save()
                with self.assertRaisesRegex(ValueError, "outside the payload"):
                    tool.load_components(self.root)

    def test_local_proxy_prototype_is_preserved_but_not_discovered(self):
        folder = self.root / "components/proxy-control"
        folder.mkdir()
        prototype = folder / "component.json"
        prototype.write_text("unmaintained local prototype")
        self.assertEqual(tool.load_components(self.root), {"demo": self.data})
        self.assertEqual(prototype.read_text(), "unmaintained local prototype")

    def test_release_cannot_depend_on_local_proxy_prototype(self):
        self.add_component("proxy-control")
        self.data["requires"] = ["proxy-control"]
        self.save()
        with self.assertRaisesRegex(ValueError, "Missing required component: proxy-control"):
            tool.load_components(self.root)

    def test_local_proxy_cannot_be_checked_or_built_explicitly(self):
        prototype = dict(self.data, id="proxy-control")
        with self.assertRaisesRegex(ValueError, "Local-only component"):
            tool.check_component(self.root, prototype)
        with self.assertRaisesRegex(ValueError, "Local-only component"):
            tool.build_component(self.root, prototype, self.root / "dist")
        self.assertFalse((self.root / "dist").exists())

    def test_active_component_cannot_package_local_proxy_script(self):
        self.data["files"][0]["source"] = "python/auto_proxy.py"
        (self.root / "python/auto_proxy.py").write_text("print('prototype')\n")
        self.save()
        with self.assertRaisesRegex(ValueError, "Local-only prototype"):
            tool.load_components(self.root)

    def configure_auto_cli(self):
        folder = self.root / "components/auto-cli"
        self.folder.rename(folder)
        self.folder = folder
        self.data["id"] = "auto-cli"
        self.data["files"] = [{"source": tool.AUTO_LAUNCHER_SOURCE,
                               "destination": tool.AUTO_LAUNCHER, "mode": "0755"}]
        source = self.root / tool.AUTO_LAUNCHER_SOURCE
        source.parent.mkdir()
        source.write_bytes(tool.AUTO_LAUNCHER_CONTENT)
        self.add_docs(self.data)
        self.save()

    def test_exact_auto_cli_launcher_is_allowed(self):
        self.configure_auto_cli()
        self.assertEqual(tool.load_components(self.root)["auto-cli"], self.data)

    def test_usr_bin_exception_cannot_be_used_by_other_components(self):
        self.data["files"][0]["destination"] = "usr/bin/auto"
        self.invalid()

    def test_auto_launcher_rejects_other_source_destination_or_mode(self):
        self.configure_auto_cli()
        original = copy.deepcopy(self.data["files"][0])
        for key, value in (("source", "python/demo.py"),
                           ("destination", "usr/bin/other"), ("mode", "0644")):
            with self.subTest(key=key):
                self.data["files"][0] = {**original, key: value}
                self.invalid()

    def test_auto_launcher_cannot_contain_additional_commands(self):
        self.configure_auto_cli()
        (self.root / tool.AUTO_LAUNCHER_SOURCE).write_bytes(tool.AUTO_LAUNCHER_CONTENT + b"id\n")
        with self.assertRaisesRegex(ValueError, "must only execute"):
            tool.load_components(self.root)

    def test_default_selection_is_never_implicit(self):
        self.data["default_enabled"] = True
        self.invalid()

    def test_arbitrary_install_hooks_are_rejected(self):
        self.data["install"] = "curl example | sh"
        self.invalid()

    def test_source_escape_and_destination_escape(self):
        for key in ("source", "destination"):
            original = self.data["files"][0][key]
            for value in ("/etc/passwd", "../secret", "python/../../secret", "C:\\secret", "etc//passwd"):
                with self.subTest(key=key, value=value):
                    self.data["files"][0][key] = value
                    self.invalid()
            self.data["files"][0][key] = original

    def test_source_symlink_is_rejected(self):
        script = self.root / "python/demo.py"
        script.unlink()
        script.symlink_to(self.folder / "README.md")
        self.invalid()

    def test_duplicate_destinations_rejected(self):
        self.data["files"].append(copy.deepcopy(self.data["files"][0]))
        self.invalid()

    def test_invalid_modes_and_package_names_rejected(self):
        self.data["files"][0]["mode"] = "4755"
        self.invalid()
        self.data["files"][0]["mode"] = "0755"
        self.data["packages"] = ["python3;shutdown"]
        self.invalid()

    def test_file_directory_destination_collisions_rejected_in_both_orders(self):
        for paths in (("etc/demo", "etc/demo/config"), ("etc/demo/config", "etc/demo")):
            with self.subTest(paths=paths):
                self.data["files"] = [dict(self.data["files"][0], destination=path) for path in paths]
                self.invalid()

    def test_no_tests_is_rejected(self):
        (self.folder / "tests/test_demo.py").unlink()
        self.invalid()

    def test_duplicate_json_keys_are_rejected(self):
        (self.folder / "component.json").write_text('{"id":"demo","id":"other"}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            tool.load_components(self.root)

    def test_new_component_is_discovered_without_tool_changes(self):
        second = self.root / "components/second"
        (second / "tests").mkdir(parents=True)
        (second / "tests/test_second.py").write_text("import unittest\n")
        (second / "README.md").write_text("Second\n")
        data = copy.deepcopy(self.data)
        data["id"] = "second"
        data["files"] = data["files"][:1]
        self.add_docs(data)
        (second / "component.json").write_text(json.dumps(data))
        self.assertEqual(list(tool.load_components(self.root)), ["demo", "second"])

    def add_component(self, identifier, requires=()):
        folder = self.root / "components" / identifier
        (folder / "tests").mkdir(parents=True)
        (folder / "tests/test_component.py").write_text("import unittest\n")
        (folder / "README.md").write_text("Component\n")
        data = copy.deepcopy(self.data)
        data.update(id=identifier, requires=list(requires))
        data.pop("minimum_versions", None)
        data["files"] = data["files"][:1]
        self.add_docs(data)
        (folder / "component.json").write_text(json.dumps(data))
        return data

    def test_requires_ids_are_validated_without_hooks_or_execution(self):
        for value in ("demo", ["../other"], ["Other"], ["other", "other"], ["demo"], [1]):
            with self.subTest(requires=value):
                self.data["requires"] = value
                self.invalid()
        self.data["requires"] = []
        self.save()
        self.assertEqual(tool.load_components(self.root)["demo"]["requires"], [])

    def test_dependencies_must_exist_and_cannot_cycle(self):
        self.data["requires"] = ["runtime"]
        self.save()
        with self.assertRaisesRegex(ValueError, "Missing required component"):
            tool.load_components(self.root)
        runtime = self.add_component("runtime", ["demo"])
        with self.assertRaisesRegex(ValueError, "cycle"):
            tool.load_components(self.root)
        runtime["requires"] = []
        (self.root / "components/runtime/component.json").write_text(json.dumps(runtime))
        self.assertEqual(tool.load_components(self.root)["demo"]["requires"], ["runtime"])

    def test_three_separate_build_directories_are_byte_identical(self):
        archives = [tool.build_component(self.root, self.data, self.root.parent / (self.root.name + "-repro-" + str(i)))
                    for i in range(3)]
        for archive in archives:
            self.addCleanup(shutil.rmtree, archive.parent)
        self.assertEqual(len({artifact.read_bytes() for artifact in archives}), 1)
        self.assertEqual(len({artifact.with_name(artifact.name + ".sha256").read_bytes() for artifact in archives}), 1)

    def test_minimum_versions_check_required_and_optional_selected_components(self):
        self.data.update(requires=["runtime"], minimum_versions={"runtime":"0.1.9", "optional":"0.1.4"})
        self.save()
        runtime = self.add_component("runtime")
        with self.assertRaisesRegex(ValueError, "runtime >= 0.1.9"):
            tool.load_components(self.root)
        runtime["version"] = "0.1.10"
        (self.root / "components/runtime/component.json").write_text(json.dumps(runtime))
        self.assertEqual(len(tool.load_components(self.root)),2)
        optional = self.add_component("optional")
        with self.assertRaisesRegex(ValueError, "optional >= 0.1.4"):
            tool.load_components(self.root)
        optional["version"] = "0.1.4"
        (self.root / "components/optional/component.json").write_text(json.dumps(optional))
        self.assertEqual(len(tool.load_components(self.root)),3)

    def test_invalid_minimum_version_metadata_is_rejected(self):
        for value in ([], "1.0.0", {"demo":"1.0.0"}, {"../bad":"1.0.0"},
                      {"other":"latest"}, {"other":"01.2.3"}, {"other":1}):
            with self.subTest(minimum=value):
                self.data["minimum_versions"] = value
                self.invalid()

    def test_archive_is_reproducible_and_explicit(self):
        output = self.root / "dist"
        artifact = tool.build_component(self.root, self.data, output)
        first = artifact.read_bytes()
        # Filesystem timestamps and other files must not enter a component package.
        (self.root / "personal-secret.txt").write_text("not included")
        (self.root / "python/demo.py").touch()
        self.assertEqual(tool.build_component(self.root, self.data, output).read_bytes(), first)
        with tarfile.open(artifact) as archive:
            self.assertEqual(set(archive.getnames()), {"README.md", "component.json", "contents.json", "payload/usr/local/bin/demo",
                "payload/usr/local/share/automations/help/docs/de/demo.txt", "payload/usr/local/share/automations/help/docs/en/demo.txt"})
            self.assertEqual(archive.getmember("payload/usr/local/bin/demo").mode, 0o755)
            self.assertTrue(all(member.mtime == 0 and member.uid == 0 for member in archive.getmembers()))
            contents = json.load(archive.extractfile("contents.json"))
            for name, info in contents.items():
                self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), info["sha256"])
        self.assertIn(hashlib.sha256(first).hexdigest(), artifact.with_name(artifact.name + ".sha256").read_text())

    def test_normalized_layout_preserves_legacy_archive_bytes(self):
        local = copy.deepcopy(self.data)
        artifact = tool.build_component(self.root, self.data, self.root / "dist")
        # Fixed reference produced by the unchanged pre-layout tool, including
        # the old manifest source names, README, payload and archive metadata.
        self.assertEqual(
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "0a483ad9cfb1d54bb8bcc0dd22bb98b6d172a739d12c3d8500dc6150f38a354e",
        )
        with tarfile.open(artifact) as archive:
            manifest_bytes = archive.extractfile("component.json").read()
            exported = json.loads(manifest_bytes)
        self.assertEqual(
            [item["source"] for item in exported["files"]],
            ["kali/python/demo.py", "kali/python/docs/de/demo.txt",
             "kali/python/docs/en/demo.txt"],
        )
        record = json.loads(artifact.with_name("demo-0.1.0.json").read_text())
        self.assertEqual(
            record["manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest()
        )
        self.assertEqual(self.data, local)
        self.assertEqual(json.loads((self.folder / "component.json").read_text()), local)

    def test_bash_sources_export_legacy_names_without_changing_local_paths(self):
        source = self.root / "shell/bash/demo.sh"
        source.parent.mkdir(parents=True)
        source.write_text("#!/bin/sh\nexit 0\n")
        self.data["files"][0]["source"] = "shell/bash/demo.sh"
        self.data["files"] = self.data["files"][:1]
        self.add_docs(self.data, "shell/bash")
        self.save()
        self.assertEqual(tool.load_components(self.root)["demo"], self.data)
        artifact = tool.build_component(self.root, self.data, self.root / "dist")
        with tarfile.open(artifact) as archive:
            exported = json.load(archive.extractfile("component.json"))
            self.assertEqual(
                [item["source"] for item in exported["files"]],
                ["kali/bash/demo.sh", "kali/bash/docs/de/demo.txt",
                 "kali/bash/docs/en/demo.txt"],
            )
            self.assertEqual(
                archive.extractfile("payload/usr/local/bin/demo").read(),
                source.read_bytes(),
            )
        self.assertEqual(self.data["files"][0]["source"], "shell/bash/demo.sh")

    def test_auto_cli_zsh_exports_the_existing_component_archive_location(self):
        self.configure_auto_cli()
        source = self.root / "shell/zsh/_auto"
        source.parent.mkdir(parents=True)
        source.write_text("#compdef auto\nreturn 0\n")
        self.data["files"].append({
            "source": "shell/zsh/_auto",
            "destination": "usr/local/share/zsh/site-functions/_auto",
            "mode": "0644",
        })
        self.save()
        self.assertEqual(tool.load_components(self.root)["auto-cli"], self.data)
        local = copy.deepcopy(self.data)
        artifact = tool.build_component(self.root, self.data, self.root / "dist")
        with tarfile.open(artifact) as archive:
            exported = json.load(archive.extractfile("component.json"))
            self.assertEqual(
                exported["files"][-1]["source"],
                "components/auto-cli/files/_auto",
            )
            payload = "payload/usr/local/share/zsh/site-functions/_auto"
            self.assertEqual(archive.getmember(payload).mode, 0o644)
            self.assertEqual(archive.extractfile(payload).read(), source.read_bytes())
        self.assertEqual(self.data, local)

    def test_changed_payload_cannot_overwrite_same_version(self):
        tool.build_component(self.root, self.data, self.root / "dist")
        (self.root / "python/demo.py").write_text("print('changed')\n")
        with self.assertRaisesRegex(ValueError, "already built with different content"):
            tool.build_component(self.root, self.data, self.root / "dist")

    def test_both_help_languages_are_required(self):
        self.data["files"].pop()
        self.invalid()

    def test_document_must_belong_to_component_and_not_be_executable(self):
        self.data["files"][-1]["mode"] = "0755"
        self.invalid()
        self.data["files"][-1]["mode"] = "0644"
        self.data["files"][-1]["source"] = self.data["files"][-2]["source"]
        self.invalid()

    def test_bash_docs_are_plain_text_not_executable_shell(self):
        self.data["files"] = self.data["files"][:1]
        self.add_docs(self.data, "shell/bash")
        self.save()
        self.assertEqual(tool.load_components(self.root)["demo"], self.data)

    def test_output_symlink_cannot_overwrite_external_file(self):
        target = self.root / "untouched"
        target.write_text("original")
        output = self.root / "dist"
        output.mkdir()
        (output / "demo-0.1.0.json").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "Output file must not be a symlink"):
            tool.build_component(self.root, self.data, output)
        self.assertEqual(target.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
