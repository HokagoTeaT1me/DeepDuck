from __future__ import annotations

import json
import re
import shlex
import shutil
import socket
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SERVICE_EVIDENCE_TYPES = {
    "service_start_success",
    "service_start_failure",
    "service_process_alive",
    "service_process_exit",
    "service_port_listening",
    "service_reachable",
    "service_http_response",
    "runtime_dependency_missing",
    "nvram_dependency",
    "config_dependency",
}

SERVICE_STATES = {"not_started", "preparing", "starting", "running", "exited", "failed", "stopped"}


@dataclass
class ServiceLaunchProfile:
    binary: str
    arguments: list[str]
    environment: dict[str, str] = field(default_factory=dict)
    working_directory: str | None = "/"
    config_files: list[str] = field(default_factory=list)
    required_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    expected_ports: list[int] = field(default_factory=list)
    startup_source: str | None = None
    confidence: float = 0.0
    service: str | None = None
    config: dict[str, Any] = field(default_factory=dict)
    missing_information: list[str] = field(default_factory=list)
    nvram_dependencies: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeRepair:
    id: str
    type: str
    target: str
    reason: str
    source_evidence: list[str] = field(default_factory=list)
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRuntimeState:
    service: str
    state: str
    backend: str = "service-qemu"
    pid: int | None = None
    start_time: float | None = None
    exit_code: int | None = None
    signal: int | None = None
    duration: float | None = None
    guest_port: int | None = None
    probe_endpoint: str | None = None
    diagnosis: str | None = None
    errors: list[str] = field(default_factory=list)
    repairs: list[RuntimeRepair] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["repairs"] = [repair.to_dict() for repair in self.repairs]
        return data


@dataclass
class BootProgress:
    kernel_started: bool = False
    rootfs_mounted: bool = False
    init_started: bool = False
    shell_available: bool = False
    nvram_started: bool = False
    network_started: bool = False
    services_started: list[str] = field(default_factory=list)
    last_stage: str = "not_started"
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def reconstruct_service_startup(rootfs: str | Path, binary: str) -> ServiceLaunchProfile:
    root = Path(rootfs)
    service = Path(binary).name
    binary_path = _resolve_binary(root, binary)
    startup_source, startup_args = _find_startup_command(root, service, binary_path)
    arguments = startup_args
    confidence = 0.35
    missing_information: list[str] = []
    if startup_source and arguments:
        confidence = 0.85
    elif service == "lighttpd":
        arguments = ["-D", "-f", "/etc/lighttpd/lighttpd.conf"]
        missing_information.append("startup script did not provide a command; used firmware lighttpd config location")
        confidence = 0.55
    else:
        missing_information.append("startup command not found")

    config_files = _config_files_from_args(arguments)
    config = parse_lighttpd_config(root / config_files[0].lstrip("/")) if service == "lighttpd" and config_files else {}
    expected_ports = _expected_ports(config)
    required_paths = [binary_path]
    required_paths.extend(config_files)
    document_root = config.get("server.document-root")
    if isinstance(document_root, str):
        required_paths.append(document_root)
    writable_paths = sorted(
        {
            "/tmp",
            "/var/tmp",
            "/var/run",
            "/var/log",
            *_writable_paths_from_config(config),
        }
    )
    nvram_dependencies = detect_nvram_dependencies(root, [startup_source, *config_files])
    return ServiceLaunchProfile(
        service=service,
        binary=binary_path,
        arguments=arguments,
        environment={},
        working_directory="/",
        config_files=config_files,
        required_paths=sorted(dict.fromkeys(required_paths)),
        writable_paths=writable_paths,
        expected_ports=expected_ports,
        startup_source=startup_source,
        confidence=confidence,
        config=config,
        missing_information=missing_information,
        nvram_dependencies=nvram_dependencies,
    )


def parse_lighttpd_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    text = config_path.read_text(encoding="utf-8", errors="ignore")
    parsed: dict[str, Any] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = _strip_comment(lines[index]).strip()
        if not raw:
            index += 1
            continue
        if re.match(r"^[A-Za-z0-9_.-]+\s*(\+?=)\s*\(", raw):
            block = raw
            while ")" not in block and index + 1 < len(lines):
                index += 1
                block += "\n" + _strip_comment(lines[index])
            key, values = _parse_array_assignment(block)
            if key:
                current = parsed.get(key, [])
                parsed[key] = [*current, *values] if isinstance(current, list) else values
            index += 1
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$", raw)
        if match:
            parsed[match.group(1)] = _parse_lighttpd_value(match.group(2).strip())
        index += 1
    includes = []
    for line in lines:
        raw = _strip_comment(line).strip()
        if raw.startswith("include"):
            includes.append(raw)
    if includes:
        parsed["includes"] = includes
    return parsed


def check_runtime_dependencies(rootfs: str | Path, profile: ServiceLaunchProfile, runner: Any = None) -> dict[str, Any]:
    root = Path(rootfs)
    missing_paths = [path for path in profile.required_paths if not _root_path(root, path).exists()]
    result = {
        "success": not missing_paths,
        "missing_paths": missing_paths,
        "interpreter": None,
        "needed_libraries": [],
        "missing_libraries": [],
    }
    binary = _root_path(root, profile.binary)
    if runner is None or not binary.exists():
        return result
    program_headers = runner.run(["readelf", "-l", str(binary)], timeout=10)
    dynamic = runner.run(["readelf", "-d", str(binary)], timeout=10)
    interpreter = _parse_interpreter(program_headers.stdout or "")
    needed = _parse_needed(dynamic.stdout or "")
    missing_libs = [library for library in needed if not _find_library(root, library)]
    result.update(
        {
            "success": not missing_paths and not missing_libs and (interpreter is None or _root_path(root, interpreter).exists()),
            "interpreter": interpreter,
            "needed_libraries": needed,
            "missing_libraries": missing_libs,
        }
    )
    if interpreter and not _root_path(root, interpreter).exists():
        result["missing_paths"].append(interpreter)
    return result


def prepare_service_rootfs(
    source_rootfs: str | Path,
    service_rootfs: str | Path,
    profile: ServiceLaunchProfile,
) -> dict[str, Any]:
    source = Path(source_rootfs)
    target = Path(service_rootfs)
    reused = target.exists()
    if not reused:
        shutil.copytree(source, target, symlinks=True, ignore_dangling_symlinks=True)
    repairs: list[RuntimeRepair] = []
    for index, path in enumerate(profile.writable_paths, start=1):
        candidate = _root_path(target, path)
        if not candidate.exists():
            candidate.mkdir(parents=True, exist_ok=True)
            repairs.append(
                RuntimeRepair(
                    id=f"RR-{len(repairs) + 1:04d}",
                    type="create_writable_directory",
                    target=path,
                    reason="required writable runtime path for service startup",
                    source_evidence=profile.config_files or ([profile.startup_source] if profile.startup_source else []),
                )
            )
    return {
        "success": True,
        "service_rootfs": str(target),
        "reused": reused,
        "repairs": [repair.to_dict() for repair in repairs],
    }


def classify_service_failure(stdout: str, stderr: str, exit_code: int | None, timed_out: bool = False) -> str:
    text = f"{stdout}\n{stderr}".lower()
    if timed_out:
        return "qemu_user_failure"
    if "no such file" in text or "not found" in text:
        if "conf" in text:
            return "missing_config"
        return "missing_file"
    if "error while loading shared libraries" in text or "can't load library" in text:
        return "missing_library"
    if "permission denied" in text:
        return "permission_error"
    if "invalid option" in text or "unknown option" in text:
        return "invalid_argument"
    if "/dev/" in text and ("no such" in text or "not found" in text):
        return "missing_device"
    if "not enough entropy" in text:
        return "missing_device"
    if "nvram" in text:
        return "missing_nvram"
    if "address already in use" in text:
        return "port_in_use"
    if "bind failed" in text or "can't bind" in text or "cannot bind" in text:
        return "bind_failure"
    if "spawning fcgi failed" in text or "mod_fastcgi" in text:
        return "fastcgi_backend_failure"
    if "segmentation fault" in text or exit_code == 139:
        return "segmentation_fault"
    if "unsupported syscall" in text:
        return "unsupported_syscall"
    if exit_code not in (None, 0):
        return "daemon_exit"
    return "unknown_runtime_failure"


def parse_boot_progress(console: str) -> BootProgress:
    text = console.lower()
    progress = BootProgress()
    progress.kernel_started = "linux version" in text or "booting linux" in text
    progress.rootfs_mounted = "mounted root" in text or "vfs: mounted root" in text or "do_execve: /sbin/init" in text
    progress.init_started = "/sbin/init" in text or "init started" in text or "do_execve: /etc/preinit" in text
    progress.shell_available = "do_execve" in text and ("/bin/sh" in text or "(sh)" in text)
    progress.nvram_started = "nvrammanager" in text or "nvram_get" in text or "libnvram" in text
    progress.network_started = any(marker in text for marker in ("eth0", "br0", "lan", "wan", "ifconfig", "udhcpc"))
    for service in ("lighttpd", "dnsmasq", "miniupnpd", "uhttpd"):
        if service in text:
            progress.services_started.append(service)
    if "kernel panic" in text:
        progress.blockers.append("kernel_boot_failure")
    if "unable to mount root" in text or "no filesystem could mount root" in text:
        progress.blockers.append("rootfs_mount_failure")
    if "nvrammanager" in text and "lighttpd" not in text:
        progress.blockers.append("firmware_initialization_or_nvram")
    if "boot_timeout" in text:
        progress.blockers.append("boot_timeout")
    if progress.services_started:
        progress.last_stage = f"service:{progress.services_started[-1]}"
    elif progress.nvram_started:
        progress.last_stage = "nvram"
    elif progress.shell_available:
        progress.last_stage = "shell"
    elif progress.init_started:
        progress.last_stage = "init"
    elif progress.rootfs_mounted:
        progress.last_stage = "rootfs"
    elif progress.kernel_started:
        progress.last_stage = "kernel"
    return progress


def detect_nvram_dependencies(rootfs: Path, firmware_paths: list[str | None]) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    for firmware_path in firmware_paths:
        if not firmware_path:
            continue
        path = _root_path(rootfs, firmware_path)
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if "nvram" in line.lower():
                dependencies.append(
                    {
                        "source": firmware_path,
                        "access_method": "startup_or_config_reference",
                        "key": "",
                    }
                )
    return dependencies


def wait_for_port(host: str, port: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def probe_http(
    url: str,
    timeout_seconds: int = 5,
    max_body_preview: int = 4096,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> dict[str, Any]:
    data = None
    if body is not None and method.upper() not in {"GET", "HEAD"}:
        data = body.encode("utf-8") if isinstance(body, str) else body
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method.upper())
    start = time.monotonic()
    context = _legacy_tls_context() if url.startswith("https://") else None
    try:
        response_context = urllib.request.urlopen(request, timeout=timeout_seconds, context=context)
    except urllib.error.HTTPError as exc:
        response_context = exc
    with response_context as response:
        body = response.read(max_body_preview)
        return {
            "method": method.upper(),
            "url": url,
            "status": response.status,
            "headers": {key: value for key, value in response.headers.items()},
            "body_preview": body.decode("utf-8", errors="replace"),
            "duration": round(time.monotonic() - start, 3),
        }


def _legacy_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1
    return context


def save_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_binary(rootfs: Path, binary: str) -> str:
    if binary.startswith("/"):
        return binary
    for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        candidate = _root_path(rootfs, f"{prefix}/{binary}")
        if candidate.exists():
            return f"{prefix}/{binary}"
    return f"/usr/sbin/{binary}"


def _find_startup_command(rootfs: Path, service: str, binary_path: str) -> tuple[str | None, list[str]]:
    init_dir = rootfs / "etc" / "init.d"
    if not init_dir.exists():
        return None, []
    for path in sorted(init_dir.iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if service not in text and binary_path not in text:
            continue
        for line in text.splitlines():
            if binary_path not in line and service not in line:
                continue
            if "service_start" not in line and binary_path not in line:
                continue
            try:
                parts = shlex.split(line.strip(), comments=True, posix=True)
            except ValueError:
                continue
            if "service_start" in parts:
                parts = parts[parts.index("service_start") + 1 :]
            if parts and (parts[0] == binary_path or Path(parts[0]).name == service):
                return f"/etc/init.d/{path.name}", parts[1:]
    return None, []


def _config_files_from_args(arguments: list[str]) -> list[str]:
    files = []
    for index, item in enumerate(arguments):
        if item == "-f" and index + 1 < len(arguments):
            files.append(arguments[index + 1])
    return files


def _expected_ports(config: dict[str, Any]) -> list[int]:
    value = config.get("server.port")
    if isinstance(value, int):
        return [value]
    if isinstance(value, str) and value.isdigit():
        return [int(value)]
    return []


def _writable_paths_from_config(config: dict[str, Any]) -> list[str]:
    paths = []
    for key in ("server.pid-file", "server.errorlog"):
        value = config.get(key)
        if isinstance(value, str) and value.startswith("/"):
            paths.append(str(Path(value).parent).replace("\\", "/"))
    return paths


def _root_path(rootfs: Path, firmware_path: str) -> Path:
    return rootfs / firmware_path.lstrip("/")


def _strip_comment(line: str) -> str:
    in_quote = False
    output = []
    for char in line:
        if char == '"':
            in_quote = not in_quote
        if char == "#" and not in_quote:
            break
        output.append(char)
    return "".join(output)


def _parse_lighttpd_value(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value


def _parse_array_assignment(block: str) -> tuple[str | None, list[str]]:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*\+?=\s*\((.*)\)\s*$", block.strip(), re.S)
    if not match:
        return None, []
    values = re.findall(r'"([^"]+)"', match.group(2))
    return match.group(1), values


def _parse_interpreter(output: str) -> str | None:
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)", output)
    return match.group(1).strip() if match else None


def _parse_needed(output: str) -> list[str]:
    return re.findall(r"Shared library: \[([^\]]+)\]", output)


def _find_library(rootfs: Path, library: str) -> bool:
    for directory in ("lib", "usr/lib", "usr/local/lib"):
        if (rootfs / directory / library).exists():
            return True
    return False
