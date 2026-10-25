#!/usr/bin/env python3
"""Validate explicit component manifests and build deterministic source packages."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
AUTO_LAUNCHER = "usr/bin/auto"
AUTO_LAUNCHER_SOURCE = "common/components/auto-cli/files/auto-launcher.sh"
AUTO_LAUNCHER_CONTENT = b'#!/bin/sh\nexec /usr/local/bin/auto "$@"\n'
# Retained local experiments are neither release components nor CI inputs.
LOCAL_ONLY_COMPONENTS = frozenset({"proxy-control"})
LOCAL_ONLY_SOURCES = frozenset({
    "common/python/auto_proxy.py", "common/python/proxy_transport.py",
    "common/docs/de/proxy-control.txt", "common/docs/en/proxy-control.txt",
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_path(value):
    require(isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.+/-]+", value)),
            f"Invalid file path: {value!r}")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in value.split("/")),
            f"Path must be relative and normalized: {value}")
    return path


def regular_file(root, value):
    relative = relative_path(value)
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"Symlink is not allowed: {value}")
    require(current.is_file(), f"File is missing: {value}")
    return current


def string_list(value, label, pattern=None, nonempty=True):
    require(isinstance(value, list) and (bool(value) or not nonempty), f"Invalid list: {label}")
    require(all(isinstance(item, str) and item for item in value), f"Invalid entry: {label}")
    require(len(set(value)) == len(value), f"Duplicate entry: {label}")
    if pattern:
        require(all(re.fullmatch(pattern, item) for item in value), f"Invalid entry: {label}")



def test_directories(root, identifier):
    return [path for group in ("common", "pi4", "portable")
            if (path := Path(root) / group / "components" / identifier / "tests").is_dir()]


def load_components(root=ROOT):
    root = Path(root).resolve()
    folder = root / "common/components"
    require(folder.is_dir() and not folder.is_symlink(), "Component directory is missing or is a symlink.")
    result = {}
    for component_dir in sorted(folder.iterdir()):
        if component_dir.name in LOCAL_ONLY_COMPONENTS or not component_dir.is_dir():
            continue
        require(not component_dir.is_symlink(), "Component directory must not be a symlink.")
        path = regular_file(root, f"common/components/{component_dir.name}/component.json")
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        require(isinstance(data, dict), "Manifest must be a JSON object.")
        required = {"schema_version", "id", "version", "name", "description", "default_enabled", "targets", "packages", "files"}
        require(required <= data.keys() and not data.keys() - required - {"hardware", "requires", "minimum_versions"}, "Unknown or missing manifest fields.")
        require(type(data["schema_version"]) is int and data["schema_version"] == 1, "Unknown manifest version.")
        identifier = data["id"]
        require(isinstance(identifier, str) and ID.fullmatch(identifier) and identifier == component_dir.name,
                "Component ID must match its directory name.")
        require(isinstance(data["version"], str) and VERSION.fullmatch(data["version"]), "Version must use the X.Y.Z format.")
        require(data["default_enabled"] is False, "Optional components must be unselected by default.")
        dependencies = data.get("requires", [])
        string_list(dependencies, "Component dependencies", ID.pattern, nonempty=False)
        require(len(dependencies) <= 32 and identifier not in dependencies, "Invalid component dependencies.")
        minimum = data.get("minimum_versions", {})
        require(isinstance(minimum, dict) and len(minimum) <= 32 and all(
            isinstance(dependency, str) and ID.fullmatch(dependency) and dependency != identifier
            and isinstance(version, str) and VERSION.fullmatch(version)
            for dependency, version in minimum.items()), "Invalid component version requirement.")
        for key in ("name", "description"):
            require(isinstance(data[key], str) and bool(data[key].strip()) and len(data[key]) <= 500, f"Invalid: {key}")
        targets = data["targets"]
        require(isinstance(targets, dict) and set(targets) == {"distributions", "architectures"}, "Invalid target systems.")
        string_list(targets["distributions"], "Distributions", r"kali|debian")
        string_list(targets["architectures"], "Architectures", r"arm64|amd64|armhf")
        string_list(data["packages"], "APT packages", r"[a-z0-9][a-z0-9+.-]*", nonempty=False)
        hardware = data.get("hardware", {})
        require(isinstance(hardware, dict) and not hardware.keys() - {"usb_ids", "kernel_modules"}, "Invalid hardware specifications.")
        if "usb_ids" in hardware:
            string_list(hardware["usb_ids"], "USB-IDs", r"[0-9a-f]{4}:[0-9a-f]{4}")
        if "kernel_modules" in hardware:
            string_list(hardware["kernel_modules"], "Kernel modules", r"[a-zA-Z0-9_]+")
        require(isinstance(data["files"], list) and bool(data["files"]), "Payload files are missing.")
        destinations = set()
        for item in data["files"]:
            require(isinstance(item, dict) and set(item) == {"source", "destination", "mode"}, "Invalid file mapping.")
            source = relative_path(item["source"]).as_posix()
            require(source.startswith(("common/python/", "pi4/python/", "portable/python/", "common/completions/", "common/templates/", "common/docs/", "common/shell/bash/", "common/shell/zsh/",
                    *(f"{group}/components/{identifier}/files/" for group in ("common", "pi4", "portable")))), "Source is outside the payload directories.")
            require(source not in LOCAL_ONLY_SOURCES, "Local-only prototype files cannot be packaged.")
            regular_file(root, source)
            destination = relative_path(item["destination"]).as_posix()
            launcher = (identifier == "auto-cli" and destination == AUTO_LAUNCHER
                        and source == AUTO_LAUNCHER_SOURCE and item["mode"] == "0755")
            require(destination.startswith(("usr/local/", "etc/")) or launcher,
                    "Destination must be under usr/local/ or etc/, except the fixed auto-cli launcher.")
            if launcher:
                require(regular_file(root, source).read_bytes() == AUTO_LAUNCHER_CONTENT,
                        "The auto-cli launcher must only execute /usr/local/bin/auto with unchanged arguments.")
            require(destination not in destinations, f"Duplicate destination path: {destination}")
            require(not any(destination.startswith(existing + "/") or existing.startswith(destination + "/")
                            for existing in destinations), f"File/directory conflict: {destination}")
            destinations.add(destination)
            require(item["mode"] in ("0644", "0755"), "Only file modes 0644 and 0755 are allowed.")
        for language in ("de", "en"):
            destination = f"usr/local/share/automations/help/docs/{language}/{identifier}.txt"
            documents = [item for item in data["files"] if item["destination"] == destination]
            require(len(documents) == 1, "Each component requires German and English TXT help.")
            document = documents[0]
            require(document["source"] in (f"common/docs/{language}/{identifier}.txt", f"common/shell/bash/docs/{language}/{identifier}.txt")
                    and document["mode"] == "0644", "Invalid source or permissions for component help.")
            content = regular_file(root, document["source"]).read_bytes()
            require(len(content) <= 65536 and content.decode("utf-8").strip() and b"\0" not in content,
                    "Component help must be short UTF-8 text.")
        require(all(not item["destination"].startswith("usr/local/share/automations/help/docs/") or
                    item["destination"] in (f"usr/local/share/automations/help/docs/{lang}/{identifier}.txt" for lang in ("de", "en"))
                    for item in data["files"]), "A component may only provide its own help.")
        regular_file(root, f"common/components/{identifier}/README.md")
        directories = test_directories(root, identifier)
        require(any(list(directory.glob("test_*.py")) for directory in directories), "Component tests are missing.")
        for tests in directories:
            require(not tests.is_symlink(), "Component tests must not be symlinks.")
            for test in tests.rglob("*"):
                require(not test.is_symlink(), "Symlinks are not allowed in component tests.")
        result[identifier] = data
    require(bool(result), "No components found.")
    require(len(result) <= 256, "Too many components.")
    visited, pending = set(), set()
    def visit(identifier):
        require(identifier in result, f"Missing required component: {identifier}")
        require(identifier not in pending, "Component dependency cycle detected.")
        if identifier in visited:
            return
        pending.add(identifier)
        for dependency in result[identifier].get("requires", []):
            visit(dependency)
        pending.remove(identifier)
        visited.add(identifier)
    for identifier in result:
        visit(identifier)
        for dependency, minimum in result[identifier].get("minimum_versions", {}).items():
            if dependency in result:
                actual = result[dependency]["version"]
                require(tuple(map(int, actual.split("."))) >= tuple(map(int, minimum.split("."))),
                        f"Incompatible component version: {identifier} requires {dependency} >= {minimum}; found {actual}.")
    return result


def check_component(root, component):
    require(component["id"] not in LOCAL_ONLY_COMPONENTS, "Local-only component is excluded from checks and package builds.")
    for item in component["files"]:
        path = regular_file(root, item["source"])
        if path.suffix == ".py":
            compile(path.read_bytes(), str(path), "exec")
        elif path.suffix == ".sh" or (item["source"].startswith("common/shell/bash/") and item["mode"] == "0755"):
            subprocess.run(["bash", "-n", str(path)], check=True)
    # Fixtures model root-managed files with explicit non-writable group bits.
    # Keep their default creation permissions independent of the caller's umask.
    previous_mask = os.umask(0o022)
    try:
        total = 0
        for directory in test_directories(root, component["id"]):
            suite = unittest.TestLoader().discover(str(directory), pattern="test_*.py", top_level_dir=str(directory))
            total += suite.countTestCases()
            require(unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(), "Component tests failed.")
        require(total > 0, "No runnable component tests found.")
    finally:
        os.umask(previous_mask)


def archive_manifest(component):
    """Keep published source names stable while local files use the Kali root."""
    exported = {**component, "files": []}
    for item in component["files"]:
        source = item["source"]
        prefix, _, relative = source.partition("/")
        if prefix in ("common", "pi4", "portable"):
            source = relative
        if source.startswith("completions/"):
            source = f"components/{component['id']}/files/completion"
        if source.startswith("templates/"):
            source = "python/" + source
        if source.startswith("docs/"):
            source = "python/" + source
        if source.startswith("python/"):
            source = "kali/" + source
        elif source.startswith("shell/bash/"):
            source = "kali/bash/" + source.removeprefix("shell/bash/")
        elif component["id"] == "auto-cli" and source == "shell/zsh/_auto":
            source = "components/auto-cli/files/_auto"
        exported["files"].append({**item, "source": source})
    return exported


def build_component(root, component, output):
    """Packages files only; never installs, executes payload or downloads dependencies."""
    require(component["id"] not in LOCAL_ONLY_COMPONENTS, "Local-only component is excluded from checks and package builds.")
    exported = archive_manifest(component)
    entries = [("component.json", json_bytes(exported), 0o644),
               ("README.md", regular_file(root, f"common/components/{component['id']}/README.md").read_bytes(), 0o644)]
    for item in component["files"]:
        entries.append(("payload/" + item["destination"], regular_file(root, item["source"]).read_bytes(), int(item["mode"], 8)))
    contents = {name: {"sha256": digest(data), "size": len(data), "mode": f"{mode:04o}"} for name, data, mode in entries}
    entries.append(("contents.json", json_bytes(contents), 0o644))
    # Stable order, metadata and gzip header make identical inputs byte-identical.
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode in sorted(entries):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))
    data = buffer.getvalue()
    require(not Path(output).is_symlink(), "Output directory must not be a symlink.")
    output = Path(output).resolve()
    require(output == root / "dist" or not output.is_relative_to(root), "Output inside the repository is only allowed under dist/.")
    output.mkdir(parents=True, exist_ok=True)
    base = f"{component['id']}-{component['version']}"
    artifact = output / (base + ".tar.gz")
    for filename in (artifact, output / (base + ".tar.gz.sha256"), output / (base + ".json")):
        require(not filename.is_symlink(), "Output file must not be a symlink.")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True)
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True, capture_output=True)
    record = {"schema_version": 1, "id": component["id"], "version": component["version"],
              "artifact": artifact.name, "sha256": digest(data), "size": len(data),
              "manifest_sha256": digest(json_bytes(exported)),
              "source_revision": revision.stdout.strip() if revision.returncode == 0 else None,
              "source_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
              "files": contents}
    # Refuse silently replacing an already built version with different content.
    require(not artifact.exists() or artifact.read_bytes() == data,
            "This version was already built with different content. Increase the version or use a different output directory.")
    artifact.write_bytes(data)
    artifact.with_name(artifact.name + ".sha256").write_text(f"{digest(data)}  {artifact.name}\n", encoding="utf-8")
    artifact.with_name(base + ".json").write_bytes(json_bytes(record))
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--json", action="store_true")
    check = commands.add_parser("check")
    check.add_argument("--component", required=True)
    build = commands.add_parser("build")
    build.add_argument("--component", required=True)
    build.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        components = load_components()
        if args.command == "list":
            print(json.dumps(list(components)) if args.json else "\n".join(components))
        else:
            require(args.component in components, "Unknown component.")
            if args.command == "check":
                check_component(ROOT, components[args.component])
            else:
                print(build_component(ROOT, components[args.component], args.output))
    except (ValueError, OSError, TypeError, SyntaxError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
