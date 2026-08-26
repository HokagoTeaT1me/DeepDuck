from __future__ import annotations

import gzip
import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Callable

from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import is_within, is_windows_reparse_point, iter_files, read_prefix, safe_exists, safe_is_dir


def extract_firmware(
    path: str | Path,
    output_dir: str | Path,
    runner: CommandRunner | None = None,
    timeout: int = 600,
) -> dict:
    firmware_path = Path(path).resolve()
    extract_dir = Path(output_dir).resolve()
    extract_dir.mkdir(parents=True, exist_ok=True)

    errors: list[dict] = []
    extractor = None

    fallback = _stdlib_extract(firmware_path, extract_dir)
    if fallback["success"]:
        extractor = fallback["extractor"]
    else:
        errors.extend(fallback["errors"])
        for name, command in _external_extractors(firmware_path, extract_dir):
            if not runner:
                continue
            before = _count_files(extract_dir)
            result = runner.run(command, timeout=timeout, cwd=extract_dir)
            after = _count_files(extract_dir)
            if after > before:
                if result.exit_code == 0:
                    extractor = name
                elif extractor is None:
                    extractor = f"{name}:partial"
                post_processed = _post_process_embedded_files(extract_dir, runner, timeout, errors)
                if post_processed:
                    extractor = f"{extractor}+postprocess" if extractor else "postprocess"
                if find_rootfs_candidates(extract_dir):
                    break
            if result.exit_code != 0 or after <= before:
                errors.append(
                    {
                        "module": "extractor",
                        "tool": name,
                        "error": (result.stderr or result.stdout or "extractor failed")[:2000],
                        "recoverable": True,
                    }
                )

    if runner and fallback["success"]:
        post_processed = _post_process_embedded_files(extract_dir, runner, timeout, errors)
        if post_processed:
            extractor = f"{extractor}+postprocess" if extractor else "postprocess"

    rootfs_candidates = find_rootfs_candidates(extract_dir)
    files_extracted = _count_files(extract_dir)
    success = files_extracted > 0
    return {
        "success": success,
        "extractor": extractor or "none",
        "rootfs_candidates": [str(path) for path in rootfs_candidates],
        "files_extracted": files_extracted,
        "errors": errors,
    }


def _external_extractors(firmware_path: Path, extract_dir: Path) -> list[tuple[str, list[str]]]:
    extractors = []
    if shutil.which("unblob"):
        extractors.append(("unblob", ["unblob", "-e", str(extract_dir), str(firmware_path)]))
    if shutil.which("binwalk"):
        extractors.append(("binwalk", ["binwalk", "-eM", "--run-as=root", "--directory", str(extract_dir), str(firmware_path)]))
    return extractors


def _post_process_embedded_files(
    extract_dir: Path,
    runner: CommandRunner,
    timeout: int,
    errors: list[dict],
) -> int:
    squashfs_extractors = _squashfs_extractors()
    if not squashfs_extractors:
        return 0

    extracted = 0
    for path in list(iter_files(extract_dir)):
        if not _is_squashfs_image(path):
            continue
        for name, command_builder in squashfs_extractors:
            target = path.with_name(f"{path.name}_{name}")
            before = _count_files(target)
            if before > 0:
                break
            result = runner.run(command_builder(target, path), timeout=timeout, cwd=extract_dir)
            after = _count_files(target)
            if result.exit_code == 0 and after > before:
                extracted += after - before
                break
            if after > before:
                extracted += after - before
                break
            errors.append(
                {
                    "module": "extractor",
                    "tool": name,
                    "error": (result.stderr or result.stdout or f"{name} failed")[:2000],
                    "recoverable": True,
                }
            )
    return extracted


def _squashfs_extractors() -> list[tuple[str, Callable[[Path, Path], list[str]]]]:
    extractors = []
    if shutil.which("unsquashfs"):
        extractors.append(("unsquashfs", lambda target, image: ["unsquashfs", "-f", "-d", str(target), str(image)]))
    if shutil.which("sasquatch"):
        extractors.append(("sasquatch", lambda target, image: ["sasquatch", "-f", "-d", str(target), str(image)]))
    return extractors


def _is_squashfs_image(path: Path) -> bool:
    prefix = read_prefix(path, 4)
    return prefix in {b"hsqs", b"sqsh", b"qshs", b"shsq"}


def _stdlib_extract(firmware_path: Path, extract_dir: Path) -> dict:
    errors = []
    try:
        if zipfile.is_zipfile(firmware_path):
            with zipfile.ZipFile(firmware_path) as archive:
                _safe_extract_zip(archive, extract_dir)
            return {"success": True, "extractor": "zipfile", "errors": []}
        if tarfile.is_tarfile(firmware_path):
            with tarfile.open(firmware_path) as archive:
                _safe_extract_tar(archive, extract_dir)
            return {"success": True, "extractor": "tarfile", "errors": []}
        if firmware_path.suffix.lower() == ".gz":
            target = extract_dir / firmware_path.with_suffix("").name
            with gzip.open(firmware_path, "rb") as source, target.open("wb") as dest:
                shutil.copyfileobj(source, dest)
            return {"success": True, "extractor": "gzip", "errors": []}
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        errors.append(
            {
                "module": "extractor",
                "tool": "stdlib",
                "error": str(exc),
                "recoverable": True,
            }
        )
    if not errors:
        errors.append(
            {
                "module": "extractor",
                "tool": "stdlib",
                "error": "no supported stdlib archive format detected",
                "recoverable": True,
            }
        )
    return {"success": False, "extractor": None, "errors": errors}


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    for member in archive.getmembers():
        target = destination / member.name
        if not is_within(target, destination):
            raise tarfile.TarError(f"unsafe tar member path: {member.name}")
    try:
        archive.extractall(destination, filter="data")
    except TypeError:
        archive.extractall(destination)


def _safe_extract_zip(archive: zipfile.ZipFile, destination: Path) -> None:
    for member in archive.infolist():
        target = destination / member.filename
        if not is_within(target, destination):
            raise zipfile.BadZipFile(f"unsafe zip member path: {member.filename}")
    archive.extractall(destination)


def find_rootfs_candidates(extract_dir: Path) -> list[Path]:
    candidates: list[tuple[int, Path]] = []
    directories = [extract_dir]
    for current, dirnames, _ in os.walk(extract_dir, followlinks=False):
        current_path = Path(current)
        kept = []
        for name in dirnames:
            path = current_path / name
            try:
                if not path.is_symlink() and not is_windows_reparse_point(path):
                    kept.append(name)
            except OSError:
                continue
        dirnames[:] = kept
        if current_path != extract_dir:
            directories.append(current_path)

    for directory in directories:
        score = 0
        if safe_exists(directory / "etc" / "passwd"):
            score += 5
        if safe_is_dir(directory / "bin") or safe_is_dir(directory / "sbin"):
            score += 3
        if safe_is_dir(directory / "usr" / "bin") or safe_is_dir(directory / "usr" / "sbin"):
            score += 2
        if safe_is_dir(directory / "www") or safe_is_dir(directory / "htdocs"):
            score += 2
        if safe_is_dir(directory / "etc" / "init.d"):
            score += 2
        if score:
            candidates.append((score, directory))
    if not candidates and _count_files(extract_dir) > 0:
        return [extract_dir]
    candidates.sort(key=lambda item: (-item[0], len(item[1].parts)))
    deduped: list[Path] = []
    for _, candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped[:5]


def _count_files(root: Path) -> int:
    if not safe_exists(root, allow_symlink=True):
        return 0
    return sum(1 for _ in iter_files(root))
