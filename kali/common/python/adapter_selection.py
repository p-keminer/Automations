"""Shared bounded, TTY-only selection for external adapter commands."""
import importlib.util
from pathlib import Path
import stat
import sys

GUEST = {"interface": "autoap0", "network": "10.79.0.0/24", "address": "10.79.0.1",
         "host": "169.254.95.1", "peer": "169.254.95.2", "transit": "169.254.95.0/30"}


def choose(options, message, *, stdin=None, stdout=None):
    """Choose an existing name; never infer a preference from ordering or routing."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not options:
        raise ValueError("No eligible external interface is available.")
    if len(options) == 1:
        return options[0][0]
    if not stdin.isatty() or not stdout.isatty():
        raise ValueError(message)
    print("Select an external interface:", file=stdout)
    for index, (name, description) in enumerate(options, 1):
        print(f"  {index}. {name} — {description}", file=stdout)
    while True:
        print("Interface number or name (Ctrl+C cancels): ", end="", file=stdout, flush=True)
        answer = stdin.readline(66)
        if not answer:
            raise ValueError("Interface selection cancelled; no interface was selected.")
        if not answer.endswith("\n") or len(answer) > 65:
            raise ValueError("Interface selection is too long.")
        answer = answer.strip()
        names = [name for name, _ in options]
        if answer in names:
            return answer
        if answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(options):
            return options[int(answer)-1][0]
        print("Choose one of the listed interface numbers or names.", file=stdout)


def choose_many(options, message, *, answer=None, stdin=None, stdout=None):
    """Explicit source selection, with no default, partial match or mutation."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not options:
        raise ValueError("No sharing source is available.")
    names = [name for name, _ in options]
    if answer is None:
        if not stdin.isatty() or not stdout.isatty():
            raise ValueError(message + " Available: " + "; ".join(name + " — " + label for name, label in options))
        print("Select the networks that should receive Internet access:", file=stdout)
        for index, (name, label) in enumerate(options, 1):
            print(f"  {index}. {name} — {label}", file=stdout)
    while True:
        interactive = answer is None
        if interactive:
            print("Interface names or numbers, comma-separated (Ctrl+C cancels): ", end="", file=stdout, flush=True)
            value = stdin.readline(257)
            if not value:
                raise ValueError("Source selection cancelled; sharing was not changed.")
            if not value.endswith("\n") or len(value) > 256:
                raise ValueError("Source selection is too long.")
        else:
            value = answer
        if not isinstance(value, str) or len(value) > 256:
            raise ValueError("Invalid source selection.")
        items = value.strip().split(",")
        result = []
        for item in items:
            item = item.strip()
            if interactive and item.isascii() and item.isdecimal() and 1 <= int(item) <= len(names):
                item = names[int(item)-1]
            if item not in names:
                break
            if item not in result:
                result.append(item)
        else:
            return [name for name in names if name in result]
        if not interactive:
            raise ValueError("Choose available source names, comma-separated. Available: " + ", ".join(names))
        print("Choose only the listed names or numbers; separate multiple choices with commas.", file=stdout)



def source_peer(filename):
    """Resolve one fixed source module in the checkout's three code groups."""
    if Path(filename).name != filename or not filename.endswith('.py'):
        raise ValueError("Invalid source peer name.")
    sibling = Path(__file__).with_name(filename)
    if Path(__file__).parent.parent.name not in ('common', 'pi4', 'portable'):
        return sibling
    root = Path(__file__).resolve().parents[2]
    matches = [path for group in ('common', 'pi4', 'portable')
               if (path := root / group / 'python' / filename).is_file()]
    if len(matches) > 1:
        raise ValueError("Duplicate source peer.")
    return matches[0] if matches else sibling


def load_peer(filename, installed, module_name):
    """Load a fixed peer, or a fixed root-owned installed payload; no search path."""
    source = source_peer(filename)
    if Path(__file__).parent.name == "python" and source.is_file():
        path = source
    else:
        path = Path(installed)
        for entry in (path, *path.parents):
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("Unsafe installed Automations helper.")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None:
        from importlib.machinery import SourceFileLoader
        spec = importlib.util.spec_from_loader(module_name, SourceFileLoader(module_name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
