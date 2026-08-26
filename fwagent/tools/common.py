from __future__ import annotations

import os
import re
import hashlib
from pathlib import Path


ELF_MAGIC = b"\x7fELF"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def display_path(path: Path, root: Path | None = None) -> str:
    candidate = Path(path)
    try:
        if root:
            return "/" + candidate.absolute().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        pass
    return candidate.as_posix()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def iter_files(root: Path):
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_dirs = []
        for name in dirnames:
            path = current_path / name
            try:
                if not path.is_symlink() and not is_windows_reparse_point(path):
                    kept_dirs.append(name)
            except OSError:
                continue
        dirnames[:] = kept_dirs
        for filename in filenames:
            path = current_path / filename
            try:
                if path.is_symlink() or is_windows_reparse_point(path):
                    continue
            except OSError:
                continue
            yield path


def is_windows_reparse_point(path: Path) -> bool:
    try:
        return bool(path.stat(follow_symlinks=False).st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError:
        return True


def safe_exists(path: Path, *, allow_symlink: bool = False) -> bool:
    try:
        if not allow_symlink and (path.is_symlink() or is_windows_reparse_point(path)):
            return False
        return path.exists()
    except OSError:
        return False


def safe_is_dir(path: Path, *, allow_symlink: bool = False) -> bool:
    try:
        if not allow_symlink and (path.is_symlink() or is_windows_reparse_point(path)):
            return False
        return path.is_dir()
    except OSError:
        return False


def read_prefix(path: Path, size: int = 4096) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def is_elf(path: Path) -> bool:
    return read_prefix(path, 4) == ELF_MAGIC


def safe_read_text(path: Path, limit: int = 1024 * 1024) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def extract_ascii_strings(path: Path, *, min_length: int = 4, max_bytes: int | None = None) -> list[str]:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes or -1)
    except OSError:
        return []
    pattern = rb"[ -~]{" + str(min_length).encode("ascii") + rb",}"
    return [match.decode("ascii", errors="ignore") for match in re.findall(pattern, data)]


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
