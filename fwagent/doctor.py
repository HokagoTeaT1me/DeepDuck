from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from fwagent.dynamic.capabilities import detect_capabilities


@dataclass
class DoctorCheck:
    name: str
    command: list[str]
    required_substring: str | None = None
    path_only: bool = False
    allow_nonzero_with_output: bool = False


CHECKS = [
    DoctorCheck("Java 21", ["java", "-version"], "21"),
    DoctorCheck("file", ["file", "--version"]),
    DoctorCheck("readelf", ["readelf", "--version"]),
    DoctorCheck("objdump", ["objdump", "--version"]),
    DoctorCheck("nm", ["nm", "--version"]),
    DoctorCheck("strings", ["strings", "--version"]),
    DoctorCheck("unblob", ["unblob", "--help"]),
    DoctorCheck("binwalk", ["binwalk", "--help"]),
    DoctorCheck("unsquashfs", ["unsquashfs", "-version"], allow_nonzero_with_output=True),
    DoctorCheck("sasquatch", ["sasquatch", "-version"], allow_nonzero_with_output=True),
    DoctorCheck("7z", ["7z", "i"]),
]


def run_doctor(*, dynamic: bool = False) -> tuple[int, str]:
    lines = ["DeepDuck Environment Check", ""]
    failed = False
    for check in CHECKS:
        ok, detail = _run_check(check)
        status = "OK" if ok else "FAIL"
        failed = failed or not ok
        lines.append(f"[{status}] {check.name}: {detail}")

    ghidra_home = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
    headless = ghidra_home / "support" / "analyzeHeadless"
    if headless.exists() and os.access(headless, os.X_OK):
        version = _ghidra_version(ghidra_home)
        lines.append(f"[OK] Ghidra analyzeHeadless: {headless}")
        lines.append(f"[OK] Ghidra version: {version}")
    else:
        failed = True
        lines.append(f"[FAIL] Ghidra analyzeHeadless: missing or not executable at {headless}")

    dynamic_failed = False
    if dynamic:
        lines.extend(["", "Dynamic Runtime"])
        dynamic_failed = _append_dynamic_checks(lines)
        failed = failed or dynamic_failed

    lines.append("")
    lines.append(f"Environment: {'NOT READY' if failed else 'READY'}")
    return (1 if failed else 0), "\n".join(lines)


def _append_dynamic_checks(lines: list[str]) -> bool:
    failed = False
    caps = detect_capabilities()
    checks = [
        DoctorCheck("QEMU ARM", ["qemu-system-arm", "--version"]),
        DoctorCheck("QEMU MIPS", ["qemu-system-mips", "--version"]),
        DoctorCheck("QEMU user static", ["qemu-arm-static", "--version"]),
        DoctorCheck("network namespace tooling", ["ip", "link"]),
    ]
    for check in checks:
        ok, detail = _run_check(check)
        if ok:
            lines.append(f"[OK] {check.name}: {detail}")
        else:
            failed = True
            lines.append(f"[FAIL] {check.name}: {detail}")
    firmae = Path(os.environ.get("FIRMAE_HOME", "/opt/FirmAE")) / "run.sh"
    if firmae.exists():
        lines.append(f"[OK] FirmAE: {firmae}")
    else:
        failed = True
        lines.append(f"[FAIL] FirmAE: missing {firmae}")
    tun = Path("/dev/net/tun")
    if tun.exists():
        lines.append("[OK] /dev/net/tun")
    else:
        lines.append("[WARN] /dev/net/tun unavailable; TUN/TAP emulation may not work")
    if Path("/dev/kvm").exists():
        lines.append("[OK] KVM available")
    else:
        lines.append("[WARN] KVM unavailable; software emulation only")

    lines.append("")
    lines.append("Dynamic Runtime")
    lines.append(f"[{'OK' if caps.docker else 'FAIL'}] Docker Desktop: {'available' if caps.docker else 'not found'}")
    lines.append(f"[{'OK' if caps.qemu_arm else 'FAIL'}] QEMU ARM")
    lines.append(f"[{'OK' if caps.qemu_mips else 'FAIL'}] QEMU MIPS")
    lines.append(f"[{'OK' if caps.loop_devices else 'WARN'}] Loop Devices: {'available' if caps.loop_devices else 'unavailable'}")
    lines.append(f"[{'OK' if caps.tun else 'WARN'}] TUN/TAP: {'available' if caps.tun else 'unavailable'}")
    lines.append(
        f"[{'OK' if caps.userspace_image_builder else 'FAIL'}] Userspace Image Builder: "
        f"{'READY' if caps.userspace_image_builder else 'UNAVAILABLE'}"
    )
    lines.append(
        f"[{'OK' if caps.qemu_user_network else 'FAIL'}] QEMU User Networking: "
        f"{'READY' if caps.qemu_user_network else 'UNAVAILABLE'}"
    )
    lines.append(
        f"[{'OK' if caps.native_firmae else 'WARN'}] FirmAE Native Backend: "
        f"{'READY' if caps.native_firmae else 'UNAVAILABLE'}"
    )
    lines.append(
        f"[{'OK' if caps.compatible_backend else 'FAIL'}] Docker QEMU Backend: "
        f"{'READY' if caps.compatible_backend else 'UNAVAILABLE'}"
    )
    lines.append(
        f"[{'OK' if caps.compatible_backend else 'FAIL'}] Dynamic Validation: "
        f"{'READY' if caps.compatible_backend else 'UNAVAILABLE'}"
    )
    if not caps.compatible_backend:
        failed = True
    return failed


def _ghidra_version(ghidra_home: Path) -> str:
    properties = ghidra_home / "Ghidra" / "application.properties"
    if properties.exists():
        for line in properties.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    return "unknown"


def _run_check(check: DoctorCheck) -> tuple[bool, str]:
    executable = shutil.which(check.command[0])
    if not executable:
        return False, "not found"
    output = _run_command(check.command, allow_nonzero_with_output=check.allow_nonzero_with_output)
    if output.startswith("ERROR:"):
        return False, output
    if check.required_substring and check.required_substring not in output:
        return False, output[:300]
    first_line = output.splitlines()[0] if output.splitlines() else executable
    return True, first_line[:300]


def _run_command(command: list[str], allow_nonzero_with_output: bool = False) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"ERROR: {exc}"
    output = result.stdout.strip()
    if result.returncode != 0 and not (allow_nonzero_with_output and output):
        return f"ERROR: exit {result.returncode}: {output[:500]}"
    return output
