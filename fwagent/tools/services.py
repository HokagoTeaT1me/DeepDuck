from __future__ import annotations

from pathlib import Path

from fwagent.tools.common import display_path, iter_files, normalize_token, safe_exists, safe_read_text


KNOWN_SERVICES = {
    "httpd": "web",
    "lighttpd": "web",
    "nginx": "web",
    "boa": "web",
    "uhttpd": "web",
    "telnetd": "remote_access",
    "dropbear": "remote_access",
    "sshd": "remote_access",
    "dnsmasq": "network",
    "upnp": "upnp",
    "miniupnpd": "upnp",
    "mqtt": "messaging",
    "mosquitto": "messaging",
    "ftp": "file_transfer",
    "ftpd": "file_transfer",
    "tftpd": "file_transfer",
    "snmpd": "management",
}

STARTUP_PATH_PARTS = {
    "etc/init.d",
    "etc/rc.d",
    "etc/systemd",
    "lib/systemd",
    "usr/lib/systemd",
}

WEB_ROOTS = ("www", "htdocs", "web", "usr/www", "var/www", "cgi-bin")
WEB_SUFFIXES = {".cgi", ".php", ".lua", ".asp", ".html", ".htm", ".js"}


def discover_services(rootfs: str | Path) -> dict:
    root = Path(rootfs).resolve()
    binary_hits = _find_named_binaries(root)
    script_hits = _find_service_references(root)
    merged: dict[str, dict] = {}

    for name, paths in binary_hits.items():
        for path in paths:
            entry = merged.setdefault(
                name,
                {
                    "name": name,
                    "binary": display_path(path, root),
                    "source": display_path(path, root),
                    "category": KNOWN_SERVICES[name],
                    "confidence": 0.75,
                    "evidence": [],
                },
            )
            entry["evidence"].append({"type": "binary", "path": display_path(path, root)})

    for name, source in script_hits:
        entry = merged.setdefault(
            name,
            {
                "name": name,
                "binary": _first_binary_for_service(binary_hits, name, root),
                "source": source,
                "category": KNOWN_SERVICES[name],
                "confidence": 0.65,
                "evidence": [],
            },
        )
        entry["source"] = source
        entry["confidence"] = max(entry["confidence"], 0.9 if entry.get("binary") else 0.8)
        entry["evidence"].append({"type": "startup_reference", "path": source})

    services = sorted(merged.values(), key=lambda item: (-item["confidence"], item["name"]))
    return {"services": services}


def discover_web_surface(rootfs: str | Path) -> dict:
    root = Path(rootfs).resolve()
    roots: list[str] = []
    cgi: list[str] = []
    scripts: list[str] = []
    static_assets: list[str] = []
    candidate_backend_binaries: list[str] = []

    for rel in WEB_ROOTS:
        candidate = root / rel
        if safe_exists(candidate):
            roots.append(display_path(candidate, root))

    for path in iter_files(root):
        if path.is_symlink():
            continue
        rel_parts = path.absolute().relative_to(root).parts
        suffix = path.suffix.lower()
        if not rel_parts:
            continue
        in_web_root = rel_parts[0] in {"www", "htdocs", "web"} or "/".join(rel_parts[:2]) in {
            "usr/www",
            "var/www",
        } or "cgi-bin" in rel_parts
        if not in_web_root and suffix not in {".cgi"}:
            continue
        display = display_path(path, root)
        if suffix == ".cgi" or "cgi-bin" in rel_parts:
            cgi.append(display)
        elif suffix in {".php", ".lua", ".asp"}:
            scripts.append(display)
        elif suffix in {".html", ".htm", ".js"}:
            static_assets.append(display)

    for service_name in ("httpd", "lighttpd", "nginx", "boa", "uhttpd"):
        for path in _find_named_binaries(root).get(service_name, []):
            candidate_backend_binaries.append(display_path(path, root))

    return {
        "roots": sorted(set(roots)),
        "cgi": sorted(set(cgi)),
        "scripts": sorted(set(scripts)),
        "static_assets": sorted(set(static_assets)),
        "candidate_backend_binaries": sorted(set(candidate_backend_binaries)),
    }


def _find_named_binaries(root: Path) -> dict[str, list[Path]]:
    hits = {name: [] for name in KNOWN_SERVICES}
    for path in iter_files(root):
        if path.is_symlink():
            continue
        name = path.name.lower()
        if name in hits:
            hits[name].append(path)
    return {name: paths for name, paths in hits.items() if paths}


def _find_service_references(root: Path) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for path in _candidate_service_files(root):
        text = safe_read_text(path, limit=256 * 1024)
        if not text:
            continue
        normalized = normalize_token(text)
        for name in KNOWN_SERVICES:
            if name in normalized.split() or f"/{name}" in text.lower():
                references.append((name, display_path(path, root)))
    return references


def _candidate_service_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    explicit = [
        root / "etc" / "inittab",
        root / "etc" / "services",
    ]
    candidates.extend(path for path in explicit if safe_exists(path))
    for path in iter_files(root / "etc" if safe_exists(root / "etc") else root):
        if path.is_symlink():
            continue
        rel = path.absolute().relative_to(root).as_posix()
        if any(rel.startswith(prefix) for prefix in STARTUP_PATH_PARTS):
            candidates.append(path)
        elif rel.startswith("etc/config"):
            candidates.append(path)
        elif path.suffix.lower() in {".service", ".timer", ".socket"}:
            candidates.append(path)
    return candidates


def _first_binary_for_service(binary_hits: dict[str, list[Path]], name: str, root: Path) -> str | None:
    paths = binary_hits.get(name) or []
    return display_path(paths[0], root) if paths else None
