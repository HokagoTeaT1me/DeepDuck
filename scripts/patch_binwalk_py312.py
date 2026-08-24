#!/usr/bin/env python3
"""Patch binwalk 2.3.4 for Python 3.12 where the removed `imp` module is used."""

from pathlib import Path


ROOT = Path("/opt/FirmAE/binwalk-2.3.4/src/binwalk")

LOAD_SOURCE = "{var} = importlib.util.module_from_spec(spec); spec.loader.exec_module({var})"

REPLACEMENTS = {
    ROOT / "core" / "plugin.py": [
        ("import imp", "import importlib.util"),
        (
            "plugin = imp.load_source(module, os.path.join(plugins[key]['path'], file_name))",
            "spec = importlib.util.spec_from_file_location(module, os.path.join(plugins[key]['path'], file_name)); "
            + LOAD_SOURCE.format(var="plugin"),
        ),
        (
            "plugin = imp.load_source(module, file_path)",
            "spec = importlib.util.spec_from_file_location(module, file_path); " + LOAD_SOURCE.format(var="plugin"),
        ),
    ],
    ROOT / "core" / "module.py": [
        ("import imp", "import importlib.util"),
        (
            "user_module = imp.load_source(module_name, os.path.join(user_modules, file_name))",
            "spec = importlib.util.spec_from_file_location(module_name, os.path.join(user_modules, file_name)); "
            + LOAD_SOURCE.format(var="user_module"),
        ),
    ],
}


def main() -> None:
    for path, replacements in REPLACEMENTS.items():
        text = path.read_text(encoding="utf-8")
        for old, new in replacements:
            if old not in text:
                raise SystemExit(f"pattern not found in {path}: {old}")
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")
    print("patched binwalk for Python 3.12")


if __name__ == "__main__":
    main()
