from __future__ import annotations

import json
import os
import signal
import shutil
import socket
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from fwagent.dynamic.capabilities import detect_capabilities
from fwagent.dynamic.application import (
    ApplicationBackendFailure,
    FastCGIProcessContext,
    FastCGIRuntimeDiff,
    FastCGIRuntimeDifference,
    FastCGIRuntimeSnapshot,
    build_fastcgi_runtime_snapshot,
    classify_fastcgi_child_failure,
    compare_fastcgi_runtime_snapshots,
    compare_runtime_contexts,
    classify_application_failure,
    infer_direct_context,
    infer_fastcgi_context,
    infer_startup_stages,
    inspect_backend_binary,
    parse_qemu_strace,
    reconstruct_endpoints,
    reconstruct_fastcgi_launch,
    save_application_json,
)
from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.fastcgi_harness import default_fastcgi_params, run_fastcgi_harness
from fwagent.dynamic.compat.image_builder import FirmwareImageBuilder, UserspaceImageBuilder
from fwagent.dynamic.models import EmulationState
from fwagent.dynamic.network import EmulationNetworkBackend, UserModeNetworkBackend
from fwagent.dynamic.service import (
    RuntimeRepair,
    ServiceLaunchProfile,
    ServiceRuntimeState,
    check_runtime_dependencies,
    classify_service_failure,
    parse_boot_progress,
    prepare_service_rootfs,
    probe_http,
    reconstruct_service_startup,
    save_json,
    wait_for_port,
)
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.runtime.firmae import FirmAERuntime
from fwagent.runtime.qemu import QemuRuntime


class EmulationBackend:
    name = "base"

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        raise NotImplementedError

    def boot(self, firmware_path: str | Path, *, timeout: int = 300) -> dict[str, Any]:
        raise NotImplementedError

    def status(self) -> dict[str, Any]:
        raise NotImplementedError

    def stop(self) -> dict[str, Any]:
        raise NotImplementedError

    def logs(self, limit: int = 200) -> list[str]:
        raise NotImplementedError

    def check_environment(self) -> dict[str, Any]:
        raise NotImplementedError


class FirmAEBackend(EmulationBackend):
    name = "firmae"

    def __init__(self, workspace: str | Path, runtime: FirmAERuntime | None = None):
        self.runtime = runtime or FirmAERuntime(workspace)

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        return self.runtime.prepare(firmware_path)

    def boot(self, firmware_path: str | Path, *, timeout: int = 300) -> dict[str, Any]:
        return self.runtime.boot(firmware_path, timeout=timeout)

    def status(self) -> dict[str, Any]:
        return self.runtime.status().to_dict()

    def stop(self) -> dict[str, Any]:
        return self.runtime.stop()

    def logs(self, limit: int = 200) -> list[str]:
        return self.runtime.logs(limit=limit)

    def check_environment(self) -> dict[str, Any]:
        return self.runtime.check_environment()


class QEMUBackend(EmulationBackend):
    name = "qemu"

    def __init__(self, workspace: str | Path, runtime: QemuRuntime | None = None):
        self.runtime = runtime or QemuRuntime(workspace)

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        return {"success": True, "firmware": str(firmware_path)}

    def boot(self, firmware_path: str | Path, *, timeout: int = 300) -> dict[str, Any]:
        return self.runtime.start(firmware_path)

    def status(self) -> dict[str, Any]:
        return self.runtime.status().to_dict()

    def stop(self) -> dict[str, Any]:
        return self.runtime.stop()

    def logs(self, limit: int = 200) -> list[str]:
        return self.runtime.logs(limit=limit)

    def check_environment(self) -> dict[str, Any]:
        return self.runtime.check_environment()


class DockerQemuBackend(EmulationBackend):
    name = "docker-qemu"

    def __init__(
        self,
        workspace: str | Path,
        *,
        config: DynamicConfig | None = None,
        image_builder: FirmwareImageBuilder | None = None,
        network: EmulationNetworkBackend | None = None,
        runner=None,
    ):
        self.workspace = DynamicWorkspace(Path(workspace).parent, Path(workspace).name)
        self.config = config
        from fwagent.runtime.command import CommandRunner

        self.runner = runner or CommandRunner(self.workspace.logs_dir)
        self.image_builder = image_builder or UserspaceImageBuilder(self.runner)
        self.network = network or UserModeNetworkBackend()
        self.logs_path = self.workspace.logs_dir / "console.log"

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        report = self.workspace.load_report()
        rootfs = report.get("extraction", {}).get("rootfs")
        if not rootfs or not Path(rootfs).is_dir():
            return {"success": False, "errors": [f"rootfs not available: {rootfs}"]}
        output = self.workspace.dynamic_dir / "images" / "rootfs.ext4"
        result = self.image_builder.build(rootfs, output, size_mb=256)
        metadata = {
            "filesystem_type": result.filesystem_type,
            "image_size_mb": result.image_size_mb,
            "builder": result.builder,
            "build_duration": result.duration,
            "output_path": str(output),
        }
        (self.workspace.dynamic_dir / "images" / "image.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            "success": result.success,
            "image": str(output),
            "metadata": metadata,
            "errors": result.errors,
        }

    def boot(self, firmware_path: str | Path, *, timeout: int = 300) -> dict[str, Any]:
        prepared = self.prepare(firmware_path)
        if not prepared.get("success"):
            return {
                "success": False,
                "errors": prepared.get("errors", ["image build failed"]),
                "diagnosis": "image_build_failure",
            }
        image = prepared["image"]
        report = self.workspace.load_report()
        architecture = (report.get("platform") or {}).get("architecture")
        command = self._build_qemu_command(image, architecture)
        if command is None:
            return {
                "success": False,
                "errors": [f"unsupported architecture: {architecture}"],
                "diagnosis": "unsupported_architecture",
            }
        self.network.prepare([80])
        command.extend(self.network.qemu_args())
        self.workspace.write_log("qemu_cmd.txt", json.dumps(command, ensure_ascii=True, indent=2))
        start = time.monotonic()
        env = dict(os.environ)
        env["QEMU_AUDIO_DRV"] = "none"
        result = self.runner.run(command, timeout=timeout + 30, env=env)
        duration = round(time.monotonic() - start, 3)
        console = _read_text(self.logs_path)
        diagnosis, errors = _classify_boot(console, result.exit_code, result.timed_out)
        success = not errors and not result.timed_out and "login:" in console.lower()
        return {
            "success": success,
            "backend": self.name,
            "architecture": architecture,
            "diagnosis": diagnosis,
            "duration": duration,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "errors": errors,
            "console_tail": console[-4000:],
        }

    def status(self) -> dict[str, Any]:
        return EmulationState(backend=self.name, status="failed").to_dict()

    def stop(self) -> dict[str, Any]:
        result = self.runner.run(["pkill", "-f", "qemu-system"], timeout=10)
        return {"success": True, "stopped": True, "pkill_exit": result.exit_code}

    def logs(self, limit: int = 200) -> list[str]:
        return _read_text(self.logs_path).splitlines()[-limit:]

    def check_environment(self) -> dict[str, Any]:
        caps = detect_capabilities()
        return {
            "success": caps.compatible_backend,
            "capabilities": caps.to_dict(),
        }

    def _build_qemu_command(self, image: str, architecture: str | None) -> list[str] | None:
        arch = (architecture or "").lower()
        if arch in {"arm", "armel"}:
            return [
                "qemu-system-arm",
                "-m",
                "256",
                "-M",
                "virt-2.10",
                "-cpu",
                "cortex-a15",
                "-kernel",
                "/opt/FirmAE/binaries/zImage.armel",
                "-drive",
                f"if=none,file={image},format=raw,id=rootfs",
                "-device",
                "virtio-blk-device,drive=rootfs",
                "-append",
                "root=/dev/vda console=ttyS0 rw debug ignore_loglevel print-fatal-signals=1",
                "-serial",
                f"file:{self.logs_path}",
                "-display",
                "none",
                "-no-reboot",
            ]
        if arch in {"mips", "mipsel"}:
            return [
                "qemu-system-mipsel",
                "-m",
                "256",
                "-M",
                "malta",
                "-kernel",
                "/opt/FirmAE/binaries/vmlinux.mipsel.2",
                "-drive",
                f"if=ide,format=raw,file={image}",
                "-append",
                "root=/dev/sda1 console=ttyS0 rw debug ignore_loglevel print-fatal-signals=1",
                "-serial",
                f"file:{self.logs_path}",
                "-display",
                "none",
                "-no-reboot",
            ]
        if arch in {"mipsbe", "mipseb"}:
            return [
                "qemu-system-mips",
                "-m",
                "256",
                "-M",
                "malta",
                "-kernel",
                "/opt/FirmAE/binaries/vmlinux.mipseb.2",
                "-drive",
                f"if=ide,format=raw,file={image}",
                "-append",
                "root=/dev/sda1 console=ttyS0 rw debug ignore_loglevel print-fatal-signals=1",
                "-serial",
                f"file:{self.logs_path}",
                "-display",
                "none",
                "-no-reboot",
            ]
        return None


class FirmAECompatBackend(DockerQemuBackend):
    name = "firmae-compat"


class QemuUserServiceBackend(EmulationBackend):
    name = "service-qemu"

    def __init__(self, workspace: str | Path, runner=None):
        self.workspace = DynamicWorkspace(Path(workspace).parent, Path(workspace).name)
        from fwagent.runtime.command import CommandRunner

        self.runner = runner or CommandRunner(self.workspace.logs_dir)
        self.service_processes: dict[str, subprocess.Popen] = {}

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        report = self.workspace.load_report()
        rootfs = report.get("extraction", {}).get("rootfs")
        if not rootfs or not Path(rootfs).is_dir():
            return {"success": False, "errors": ["rootfs not available"]}
        return {"success": True, "rootfs": rootfs}

    def boot(self, firmware_path: str | Path, *, timeout: int = 120) -> dict[str, Any]:
        prepared = self.prepare(firmware_path)
        if not prepared.get("success"):
            return {"success": False, "errors": prepared.get("errors", []), "diagnosis": "backend_error"}
        rootfs = Path(prepared["rootfs"])
        shell = rootfs / "bin" / "sh"
        busybox = rootfs / "bin" / "busybox"
        executable = busybox if busybox.exists() else shell
        if not executable.exists():
            return {
                "success": False,
                "errors": [f"service executable not found: {executable}"],
                "diagnosis": "service_start_failure",
            }
        service_args = ["uname", "-m"] if executable == busybox else ["-c", "echo qemu-user-service-ok"]
        command = [
            "qemu-arm-static",
            "-L",
            str(rootfs),
            str(executable),
            *service_args,
        ]
        result = self.runner.run(command, timeout=timeout)
        output = (result.stdout or result.stderr or "")[:4000]
        return {
            "success": result.exit_code == 0,
            "backend": self.name,
            "diagnosis": "service_start_failure" if result.exit_code != 0 else "service_running",
            "exit_code": result.exit_code,
            "output": output,
        }

    def reconstruct_service_startup(self, binary: str) -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = reconstruct_service_startup(rootfs, binary)
        service_dir = self._service_dir(profile.service or Path(profile.binary).name)
        save_json(service_dir / "launch_profile.json", profile.to_dict())
        return {"success": True, "profile": profile.to_dict()}

    def prepare_service(self, service: str, *, force_reconstruct: bool = False) -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = self._load_or_reconstruct_profile(service, force_reconstruct=force_reconstruct)
        dependencies = check_runtime_dependencies(rootfs, profile, self.runner)
        if dependencies.get("missing_paths") or dependencies.get("missing_libraries"):
            result = {
                "success": False,
                "diagnosis": "missing_runtime_dependency",
                "profile": profile.to_dict(),
                "dependencies": dependencies,
            }
            save_json(self._service_dir(service) / "runtime.json", result)
            return result
        service_rootfs = self.workspace.dynamic_dir / "service-rootfs" / service
        prepared = prepare_service_rootfs(rootfs, service_rootfs, profile)
        repairs = list(prepared["repairs"])
        if profile.config.get("ssl.engine") == "enable":
            rand_file = service_rootfs / "etc" / "ssl" / "private" / ".rand"
            rand_file.parent.mkdir(parents=True, exist_ok=True)
            rand_file.write_bytes(os.urandom(4096))
            profile.environment["RANDFILE"] = "/etc/ssl/private/.rand"
            repairs.append(
                {
                    "id": f"RR-{len(repairs) + 1:04d}",
                    "type": "create_entropy_seed",
                    "target": "/etc/ssl/private/.rand",
                    "reason": "firmware lighttpd enables SSL and OpenSSL requires runtime entropy",
                    "source_evidence": profile.config_files,
                    "reversible": True,
                }
            )
        qemu = shutil.which("qemu-arm-static")
        if qemu:
            qemu_target = service_rootfs / "usr" / "bin" / "qemu-arm-static"
            qemu_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(qemu, qemu_target)
        result = {
            "success": True,
            "service": service,
            "profile": profile.to_dict(),
            "dependencies": dependencies,
            "service_rootfs": str(service_rootfs),
            "repairs": repairs,
        }
        service_dir = self._service_dir(service)
        save_json(service_dir / "launch_profile.json", profile.to_dict())
        save_json(service_dir / "runtime.json", result)
        return result

    def start_service(
        self,
        service: str,
        *,
        stability_seconds: int = 5,
        _allow_fastcgi_repair: bool = True,
    ) -> dict[str, Any]:
        prepared = self.prepare_service(service)
        if not prepared.get("success"):
            return prepared
        profile = ServiceLaunchProfile(**prepared["profile"])
        service_dir = self._service_dir(service)
        stdout_path = service_dir / "stdout.log"
        stderr_path = service_dir / "stderr.log"
        runtime_rootfs = Path(prepared["service_rootfs"])
        command = self._service_command(runtime_rootfs, profile)
        env = dict(os.environ)
        env.update(profile.environment)
        stdout = stdout_path.open("ab")
        stderr = stderr_path.open("ab")
        start = time.monotonic()
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, cwd="/", env=env)
        except OSError as exc:
            stdout.close()
            stderr.close()
            state = ServiceRuntimeState(
                service=service,
                state="failed",
                diagnosis="qemu_user_failure",
                errors=[str(exc)],
            )
            save_json(service_dir / "runtime.json", state.to_dict())
            return {"success": False, "state": state.to_dict(), "command": command}
        self.service_processes[service] = process
        time.sleep(max(0, stability_seconds))
        exit_code = process.poll()
        duration = round(time.monotonic() - start, 3)
        if exit_code is None:
            port = profile.expected_ports[0] if profile.expected_ports else None
            scheme = "https" if profile.config.get("ssl.engine") == "enable" else "http"
            endpoint = f"{scheme}://127.0.0.1:{port}/" if port else None
            state = ServiceRuntimeState(
                service=service,
                state="running",
                pid=process.pid,
                start_time=start,
                duration=duration,
                guest_port=port,
                probe_endpoint=endpoint,
                diagnosis="service_running",
            )
            result = {"success": True, "state": state.to_dict(), "command": command}
        else:
            stdout.close()
            stderr.close()
            stdout_text = _read_text(stdout_path)
            stderr_text = _read_text(stderr_path)
            diagnosis = classify_service_failure(stdout_text, stderr_text, exit_code)
            state = ServiceRuntimeState(
                service=service,
                state="exited",
                pid=process.pid,
                start_time=start,
                exit_code=exit_code,
                duration=duration,
                diagnosis=diagnosis,
                errors=[(stderr_text or stdout_text or "service exited")[-1000:]],
            )
            result = {"success": False, "state": state.to_dict(), "command": command}
            if _allow_fastcgi_repair and diagnosis == "fastcgi_backend_failure":
                repair = self._disable_lighttpd_fastcgi_backend(runtime_rootfs, profile)
                if repair.get("success"):
                    save_json(service_dir / "baseline_failure.json", result)
                    profile.arguments = _replace_config_argument(profile.arguments, repair["config_file"])
                    profile.config_files = [repair["config_file"]]
                    modules = profile.config.get("server.modules")
                    if isinstance(modules, list):
                        profile.config["server.modules"] = [module for module in modules if module != "mod_fastcgi"]
                    profile.config.pop("fastcgi.server", None)
                    profile.config.pop("fastcgi.debug", None)
                    save_json(service_dir / "launch_profile.json", profile.to_dict())
                    retry = self.start_service(
                        service,
                        stability_seconds=stability_seconds,
                        _allow_fastcgi_repair=False,
                    )
                    retry["baseline_failure"] = result
                    retry["runtime_repairs"] = [repair]
                    save_json(service_dir / "runtime.json", retry)
                    return retry
        save_json(service_dir / "runtime.json", result)
        return result

    def get_service_status(self, service: str) -> dict[str, Any]:
        process = self.service_processes.get(service)
        runtime_path = self._service_dir(service) / "runtime.json"
        if process is None:
            if runtime_path.exists():
                data = json.loads(runtime_path.read_text(encoding="utf-8"))
                state = data.get("state", data)
                pid = state.get("pid") if isinstance(state, dict) else None
                if pid and _pid_running(int(pid)):
                    state["state"] = "running"
                    return {"success": True, "state": state}
                return {"success": False, "state": state, "errors": ["service process is not active in this runtime"]}
            return {"success": False, "errors": ["service runtime state not found"]}
        exit_code = process.poll()
        state = "running" if exit_code is None else "exited"
        return {
            "success": exit_code is None,
            "state": {
                "service": service,
                "state": state,
                "pid": process.pid,
                "exit_code": exit_code,
                "backend": self.name,
            },
        }

    def get_service_logs(self, service: str, *, lines: int = 100) -> dict[str, Any]:
        service_dir = self._service_dir(service)
        return {
            "success": True,
            "service": service,
            "stdout": _tail(service_dir / "stdout.log", lines),
            "stderr": _tail(service_dir / "stderr.log", lines),
        }

    def get_service_ports(self, service: str, *, timeout_seconds: int = 1) -> dict[str, Any]:
        profile = self._load_or_reconstruct_profile(service)
        ports = []
        for port in profile.expected_ports:
            listening = wait_for_port("127.0.0.1", port, timeout_seconds)
            ports.append({"protocol": "tcp", "port": port, "state": "listening" if listening else "closed"})
        return {"success": any(item["state"] == "listening" for item in ports), "service": service, "ports": ports}

    def probe_service_http(self, service: str) -> dict[str, Any]:
        profile = self._load_or_reconstruct_profile(service)
        if not profile.expected_ports:
            return {"success": False, "errors": ["service has no expected HTTP port"]}
        schemes = ["https", "http"] if profile.config.get("ssl.engine") == "enable" else ["http", "https"]
        errors = []
        for scheme in schemes:
            url = f"{scheme}://127.0.0.1:{profile.expected_ports[0]}/"
            try:
                result = probe_http(url)
            except Exception as exc:  # noqa: BLE001 - runtime probe is structured
                errors.append(f"{url}: {exc}")
                continue
            return {"success": True, "service": service, "result": result}
        return {"success": False, "service": service, "errors": errors}

    def _disable_lighttpd_fastcgi_backend(self, runtime_rootfs: Path, profile: ServiceLaunchProfile) -> dict[str, Any]:
        if profile.service != "lighttpd" or not profile.config_files:
            return {"success": False, "errors": ["FastCGI repair is only supported for reconstructed lighttpd profiles"]}
        source_config = profile.config_files[0]
        source_path = runtime_rootfs / source_config.lstrip("/")
        if not source_path.exists():
            return {"success": False, "errors": [f"lighttpd config not found: {source_config}"]}
        runtime_config = str(PurePosixPath(source_config).with_name("lighttpd.fwagent-runtime.conf"))
        runtime_path = runtime_rootfs / runtime_config.lstrip("/")
        repaired = _lighttpd_without_fastcgi(source_path.read_text(encoding="utf-8", errors="replace"))
        runtime_path.write_text(repaired, encoding="utf-8")
        return {
            "success": True,
            "id": "RR-0005",
            "type": "disable_unavailable_fastcgi_backend",
            "target": runtime_config,
            "reason": "firmware FastCGI child exits under qemu-user; disable dependent backend to validate lighttpd reachability",
            "source_evidence": [source_config, str(self._service_dir(profile.service) / "baseline_failure.json")],
            "reversible": True,
            "config_file": runtime_config,
        }

    def _external_fastcgi_runtime_repair(
        self,
        runtime_rootfs: Path,
        profile: ServiceLaunchProfile,
        endpoint: str,
        *,
        backend: str = "device_manager",
        socket_guest: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> dict[str, Any]:
        if profile.service != "lighttpd" or not profile.config_files:
            return {"success": False, "errors": ["external FastCGI repair requires a reconstructed lighttpd profile"]}
        source_config = profile.config_files[0]
        source_path = runtime_rootfs / source_config.lstrip("/")
        if not source_path.exists():
            return {"success": False, "errors": [f"lighttpd config not found: {source_config}"]}
        runtime_config = str(PurePosixPath(source_config).with_name("lighttpd.fwagent-fastcgi-external.conf"))
        runtime_path = runtime_rootfs / runtime_config.lstrip("/")
        repaired = _lighttpd_external_fastcgi(
            source_path.read_text(encoding="utf-8", errors="replace"),
            socket_guest=socket_guest,
            host=host,
            port=port,
            endpoint=endpoint,
        )
        runtime_path.write_text(repaired, encoding="utf-8")
        repair = RuntimeRepair(
            id="RR-3501",
            type="external_fastcgi_lifecycle_parity",
            target=runtime_config,
            reason="Runtime differential showed standalone FastCGI responder is stable with FD0 listener while lighttpd-managed spawn exits before request handling; preserve lighttpd routing but connect it to an externally started firmware FastCGI child.",
            source_evidence=[
                str(self._application_dir(backend) / "runtime_diff.json"),
                str(self._application_dir(backend) / "harness_result.json"),
                source_config,
            ],
            reversible=True,
        ).to_dict()
        transport = "unix" if socket_guest else "tcp"
        repair.update(
            {
                "success": True,
                "config_file": runtime_config,
                "socket": socket_guest,
                "host": host,
                "port": port,
                "transport": transport,
                "endpoint": endpoint,
                "scope": "dynamic/service-rootfs",
                "source_rootfs_modified": False,
            }
        )
        save_json(self._service_dir(profile.service) / "fastcgi_external_repair.json", repair)
        return repair

    def stop_service(self, service: str) -> dict[str, Any]:
        process = self.service_processes.get(service)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        state = ServiceRuntimeState(service=service, state="stopped")
        save_json(self._service_dir(service) / "runtime.json", {"success": True, "state": state.to_dict()})
        return {"success": True, "service": service, "state": state.to_dict()}

    def get_boot_progress(self) -> dict[str, Any]:
        console = _read_text(self.workspace.logs_dir / "console.log")
        progress = parse_boot_progress(console)
        return {"success": True, "boot_progress": progress.to_dict()}

    def inspect_application_backend(self, backend: str = "device_manager") -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        binary = _application_binary(backend)
        result = inspect_backend_binary(rootfs, binary, self.runner)
        app_dir = self._application_dir(backend)
        save_application_json(app_dir / "binary.json", result)
        return result

    def get_application_dependencies(self, backend: str = "device_manager") -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = reconstruct_fastcgi_launch(rootfs, _application_binary(backend), self.runner)
        result = {
            "success": True,
            "backend": backend,
            "dependencies": [dependency.to_dict() for dependency in profile.dependencies],
        }
        save_application_json(self._application_dir(backend) / "dependencies.json", result)
        return result

    def get_fastcgi_launch_profile(self, backend: str = "device_manager") -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = reconstruct_fastcgi_launch(rootfs, _application_binary(backend), self.runner)
        result = {"success": True, "backend": backend, "profile": profile.to_dict()}
        save_application_json(self._application_dir(backend) / "profile.json", result)
        return result

    def trace_application_startup(
        self,
        backend: str = "device_manager",
        *,
        timeout_seconds: int = 10,
        max_events: int = 2000,
    ) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        service_profile = ServiceLaunchProfile(**prepared["profile"])
        app_dir = self._application_dir(backend)
        trace_path = app_dir / "trace.log"
        stdout_path = app_dir / "logs" / "trace_stdout.log"
        stderr_path = app_dir / "logs" / "trace_stderr.log"
        command = self._service_command(runtime_rootfs, service_profile, qemu_args=["-strace"])
        env = dict(os.environ)
        env.update(service_profile.environment)
        result = self.runner.run(command, timeout=max(1, min(timeout_seconds, 30)), cwd=Path("/"), env=env)
        self.runner.run(["pkill", "-f", "qemu-arm-static"], timeout=5)
        stderr = _read_text(result.stderr)
        stdout = _read_text(result.stdout)
        trace_path.write_text(stderr, encoding="utf-8")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        parsed = parse_qemu_strace(stderr, max_events=max_events)
        payload = {
            "success": True,
            "backend": backend,
            "command": command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration": round(result.duration, 3),
            "trace": parsed,
        }
        save_application_json(app_dir / "trace.json", payload)
        return payload

    def get_direct_application_context(self, backend: str = "device_manager", *, timeout_seconds: int = 10) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        binary = _application_binary(backend)
        app_dir = self._application_dir(backend)
        command = self._backend_command(runtime_rootfs, binary, qemu_args=["-strace"])
        start = time.monotonic()
        result = self.runner.run(command, timeout=max(1, min(timeout_seconds, 30)), cwd=Path("/"), env=_minimal_firmware_env())
        stdout = _read_text(result.stdout)
        stderr = _read_text(result.stderr)
        context = infer_direct_context(command, stderr, cwd="/", environment=_minimal_firmware_env())
        payload = {
            "success": True,
            "backend": backend,
            "kind": "direct_exec",
            "command": command,
            "context": context.to_dict(),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration": round(time.monotonic() - start, 3),
            "stdout_preview": stdout[:4000],
            "stderr_preview": stderr[-4000:],
        }
        direct_dir = app_dir / "direct_exec"
        save_application_json(direct_dir / "context.json", payload)
        (direct_dir / "trace.log").write_text(stderr, encoding="utf-8")
        return payload

    def get_fastcgi_application_context(self, backend: str = "device_manager", *, timeout_seconds: int = 10) -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        trace = self.trace_application_startup(backend, timeout_seconds=timeout_seconds, max_events=2000)
        profile = reconstruct_fastcgi_launch(rootfs, _application_binary(backend), self.runner)
        trace_text = _read_text(self._application_dir(backend) / "logs" / "trace_stderr.log")
        context = infer_fastcgi_context(trace_text, profile)
        payload = {
            "success": True,
            "backend": backend,
            "kind": "lighttpd_fastcgi",
            "context": context.to_dict(),
            "trace": trace,
            "profile": profile.to_dict(),
        }
        save_application_json(self._application_dir(backend) / "fastcgi_context.json", payload)
        return payload

    def compare_application_runtime_contexts(self, backend: str = "device_manager") -> dict[str, Any]:
        app_dir = self._application_dir(backend)
        direct_path = app_dir / "direct_exec" / "context.json"
        fastcgi_path = app_dir / "fastcgi_context.json"
        if not direct_path.exists():
            self.get_direct_application_context(backend)
        if not fastcgi_path.exists():
            self.get_fastcgi_application_context(backend)
        direct_data = json.loads(direct_path.read_text(encoding="utf-8"))
        fastcgi_data = json.loads(fastcgi_path.read_text(encoding="utf-8"))
        direct = infer_context_from_dict(direct_data["context"])
        fastcgi = infer_context_from_dict(fastcgi_data["context"])
        diff = compare_runtime_contexts(direct, fastcgi)
        result = {"success": True, "backend": backend, "diff": diff}
        save_application_json(app_dir / "context_diff.json", result)
        return result

    def get_application_startup_graph(self, backend: str = "device_manager") -> dict[str, Any]:
        app_dir = self._application_dir(backend)
        trace_text = _read_text(app_dir / "logs" / "trace_stderr.log")
        stderr_text = _read_text(app_dir / "logs" / "startup_stderr.log")
        stages = infer_startup_stages(trace_text, stderr_text)
        result = {"success": True, "backend": backend, "stages": [stage.to_dict() for stage in stages]}
        save_application_json(app_dir / "startup_graph.json", result)
        return result

    def start_fastcgi_harness(
        self,
        backend: str = "device_manager",
        *,
        endpoint: str = "/services/device_manager/",
        timeout_seconds: int = 10,
    ) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        binary = _application_binary(backend)
        app_dir = self._application_dir(backend)
        runtime_dir = Path("/tmp") / "fwagent-fastcgi-harness"
        command = self._backend_command(
            runtime_rootfs,
            binary,
            cwd=str(PurePosixPath(binary).parent),
        )
        params = default_fastcgi_params()
        params["REQUEST_URI"] = endpoint
        params["SCRIPT_NAME"] = endpoint
        result = run_fastcgi_harness(
            command,
            runtime_dir=runtime_dir,
            socket_name=f"fwagent-{backend}.sock",
            params=params,
            timeout_seconds=max(1, min(timeout_seconds, 30)),
            cwd="/",
            env=_minimal_firmware_env(),
        )
        result["success"] = bool(result.get("backend_started"))
        result["backend"] = backend
        result["endpoint"] = endpoint
        result["command"] = command
        save_application_json(app_dir / "harness_result.json", result)
        return result

    def get_fastcgi_runtime_context(
        self,
        backend: str = "device_manager",
        *,
        mode: str = "standalone",
        timeout_seconds: int = 10,
    ) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = reconstruct_fastcgi_launch(rootfs, _application_binary(backend), self.runner)
        app_dir = self._application_dir(backend)
        if mode == "standalone":
            harness_path = app_dir / "harness_result.json"
            harness = (
                json.loads(harness_path.read_text(encoding="utf-8"))
                if harness_path.exists()
                else self.start_fastcgi_harness(backend, timeout_seconds=timeout_seconds)
            )
            command = list(harness.get("command") or self._backend_command(runtime_rootfs, profile.binary, cwd=str(PurePosixPath(profile.binary).parent)))
            context = FastCGIProcessContext(
                argv=command,
                environment=_minimal_firmware_env(),
                cwd=str(PurePosixPath(profile.binary).parent),
                stdin_fd={"fd": 0, "type": "fastcgi_listen_socket", "role": "FCGI_LISTENSOCK_FILENO"},
                stdout_fd={"fd": 1, "type": "captured_pipe", "role": "stdout"},
                stderr_fd={"fd": 2, "type": "captured_pipe", "role": "stderr"},
                listen_socket_fd=0,
                parent_pid=None,
            )
            snapshot = build_fastcgi_runtime_snapshot(
                mode="standalone",
                backend=backend,
                executable=profile.binary,
                command=command,
                context=context,
                profile=profile,
                filesystem_root=str(runtime_rootfs),
                harness_result=harness,
            )
        elif mode == "lighttpd":
            fastcgi = self.get_fastcgi_application_context(backend, timeout_seconds=timeout_seconds)
            if not fastcgi.get("success"):
                return fastcgi
            context = infer_context_from_dict(fastcgi["context"])
            startup_path = app_dir / "startup.json"
            startup = json.loads(startup_path.read_text(encoding="utf-8")) if startup_path.exists() else {}
            snapshot = build_fastcgi_runtime_snapshot(
                mode="lighttpd",
                backend=backend,
                executable=profile.binary,
                command=list(fastcgi.get("trace", {}).get("command") or []),
                context=context,
                profile=profile,
                filesystem_root=str(runtime_rootfs),
                startup_result=startup,
                trace=fastcgi.get("trace") or {},
            )
        else:
            return {"success": False, "errors": [f"unknown FastCGI runtime mode: {mode}"]}
        result = {"success": True, "backend": backend, "mode": mode, "snapshot": snapshot.to_dict()}
        save_application_json(app_dir / f"{mode}_runtime_snapshot.json", result)
        return result

    def compare_fastcgi_runtime(self, backend: str = "device_manager") -> dict[str, Any]:
        standalone = self.get_fastcgi_runtime_context(backend, mode="standalone")
        lighttpd = self.get_fastcgi_runtime_context(backend, mode="lighttpd")
        if not standalone.get("success"):
            return standalone
        if not lighttpd.get("success"):
            return lighttpd
        diff = compare_fastcgi_runtime_snapshots(
            infer_runtime_snapshot_from_dict(standalone["snapshot"]),
            infer_runtime_snapshot_from_dict(lighttpd["snapshot"]),
        )
        result = {"success": True, "backend": backend, "diff": diff.to_dict()}
        save_application_json(self._application_dir(backend) / "runtime_diff.json", result)
        return result

    def get_fastcgi_child_failure(self, backend: str = "device_manager", *, stability_seconds: int = 5) -> dict[str, Any]:
        startup = self.start_application_backend(backend, stability_seconds=stability_seconds)
        app_dir = self._application_dir(backend)
        diff_path = app_dir / "runtime_diff.json"
        diff = None
        if diff_path.exists():
            diff_data = json.loads(diff_path.read_text(encoding="utf-8"))
            diff = diff_data.get("diff")
        failure = startup.get("failure") or {}
        classification = classify_fastcgi_child_failure(
            exit_code=182 if failure.get("diagnosis") == "fastcgi_child_exit_182" else failure.get("exit_code"),
            signal=failure.get("signal"),
            stderr=failure.get("stderr_preview", ""),
            stdout=failure.get("stdout_preview", ""),
            diff=infer_runtime_diff_from_dict(diff) if isinstance(diff, dict) else None,
        )
        result = {
            "success": True,
            "backend": backend,
            "startup": startup,
            "classification": classification,
            "last_log_lines": _tail(app_dir / "logs" / "startup_stderr.log", 80),
        }
        save_application_json(app_dir / "child_failure.json", result)
        return result

    def validate_fastcgi_integration(
        self,
        backend: str = "device_manager",
        *,
        endpoint: str = "/services/device_manager/",
        stability_seconds: int = 3,
        safe_inputs: list[dict[str, Any]] | None = None,
        max_response_preview: int = 512,
    ) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        service_profile = ServiceLaunchProfile(**prepared["profile"])
        app_dir = self._application_dir(backend)
        binary = _application_binary(backend)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener_host, listener_port = listener.getsockname()
        repair = self._external_fastcgi_runtime_repair(
            runtime_rootfs,
            service_profile,
            endpoint,
            backend=backend,
            host=str(listener_host),
            port=int(listener_port),
        )
        if not repair.get("success"):
            listener.close()
            return repair
        backend_stdout_path = app_dir / "logs" / "integration_backend_stdout.log"
        backend_stderr_path = app_dir / "logs" / "integration_backend_stderr.log"
        lighttpd_stdout_path = app_dir / "logs" / "integration_lighttpd_stdout.log"
        lighttpd_stderr_path = app_dir / "logs" / "integration_lighttpd_stderr.log"
        for path in (backend_stdout_path, backend_stderr_path, lighttpd_stdout_path, lighttpd_stderr_path):
            path.parent.mkdir(parents=True, exist_ok=True)
        command_rootfs = runtime_rootfs
        backend_command = self._backend_command(command_rootfs, binary, cwd=str(PurePosixPath(binary).parent))
        backend_stdout = backend_stdout_path.open("wb")
        backend_stderr = backend_stderr_path.open("wb")
        lighttpd_stdout = lighttpd_stdout_path.open("wb")
        lighttpd_stderr = lighttpd_stderr_path.open("wb")
        backend_process = None
        lighttpd_process = None
        probe = None
        request_observations: list[dict[str, Any]] = []
        errors: list[str] = []
        result: dict[str, Any] | None = None
        try:
            try:
                backend_process = subprocess.Popen(
                    backend_command,
                    stdin=listener,
                    stdout=backend_stdout,
                    stderr=backend_stderr,
                    cwd="/",
                    env=_minimal_firmware_env(),
                    close_fds=True,
                    start_new_session=os.name != "nt",
                )
            except OSError as exc:
                errors.append(f"backend_start: {exc}")
                result = _fastcgi_integration_blocked_result(
                    backend=backend,
                    endpoint=endpoint,
                    repair=repair,
                    backend_command=backend_command,
                    listener_host=str(listener_host),
                    listener_port=int(listener_port),
                    errors=errors,
                    blocked_reason=f"FastCGI child could not inherit the loopback listener as stdin on this host runtime: {exc}",
                )
                raise _FastCGIIntegrationBlocked()
            listener.close()
            time.sleep(0.5)
            backend_alive = backend_process.poll() is None
            repaired_profile = ServiceLaunchProfile(
                service="lighttpd",
                binary="/usr/sbin/lighttpd",
                arguments=["-D", "-f", repair["config_file"]],
                environment=service_profile.environment,
                working_directory="/",
                config_files=[repair["config_file"]],
                expected_ports=service_profile.expected_ports,
                config=service_profile.config,
            )
            lighttpd_command = self._service_command(command_rootfs, repaired_profile)
            env = dict(os.environ)
            env.update(service_profile.environment)
            try:
                lighttpd_process = subprocess.Popen(
                    lighttpd_command,
                    stdout=lighttpd_stdout,
                    stderr=lighttpd_stderr,
                    cwd="/",
                    env=env,
                    start_new_session=os.name != "nt",
                )
            except OSError as exc:
                errors.append(f"lighttpd_start: {exc}")
                result = _fastcgi_integration_blocked_result(
                    backend=backend,
                    endpoint=endpoint,
                    repair=repair,
                    backend_command=backend_command,
                    listener_host=str(listener_host),
                    listener_port=int(listener_port),
                    errors=errors,
                    blocked_reason=f"lighttpd service command could not start on this host runtime: {exc}",
                    lighttpd_command=lighttpd_command,
                    backend_alive=backend_alive,
                )
                raise _FastCGIIntegrationBlocked()
            time.sleep(max(0, stability_seconds))
            lighttpd_alive = lighttpd_process.poll() is None
            port = service_profile.expected_ports[0] if service_profile.expected_ports else 3000
            schemes = ["https", "http"] if service_profile.config.get("ssl.engine") == "enable" else ["http", "https"]
            validation_inputs = safe_inputs or [
                {
                    "input_id": "VI-0001",
                    "method": "GET",
                    "path": endpoint,
                    "headers": {},
                    "body": "",
                    "category": "baseline",
                }
            ]
            for item in validation_inputs:
                item_probe = None
                item_errors = []
                request_path = str(item.get("path") or endpoint)
                method = str(item.get("method") or "GET").upper()
                headers = {str(key): str(value) for key, value in (item.get("headers") or {}).items()}
                body_value = str(item.get("body") or "")
                for scheme in schemes:
                    try:
                        item_probe = probe_http(
                            f"{scheme}://127.0.0.1:{port}{request_path}",
                            timeout_seconds=5,
                            max_body_preview=max_response_preview,
                            method=method,
                            headers=headers,
                            body=body_value,
                        )
                        break
                    except Exception as exc:  # noqa: BLE001 - integration probe is structured
                        item_errors.append(f"{scheme}: {exc}")
                backend_after = backend_process.poll() is None
                lighttpd_after = lighttpd_process.poll() is None
                request_observations.append(
                    {
                        "input_id": str(item.get("input_id") or f"VI-{len(request_observations) + 1:04d}"),
                        "category": item.get("category"),
                        "method": method,
                        "path": request_path,
                        "probe": item_probe,
                        "errors": item_errors,
                        "backend_alive_after": backend_after,
                        "lighttpd_alive_after": lighttpd_after,
                    }
                )
                if probe is None and item_probe is not None:
                    probe = item_probe
                if item_probe is None:
                    errors.extend(item_errors)
                if not backend_after or not lighttpd_after:
                    break
            body = (probe or {}).get("body_preview", "")
            headers = (probe or {}).get("headers", {})
            application_response = bool(
                probe
                and (
                    "Unknown SOAP action" in body
                    or "soap:Fault" in body
                    or "TPRA IOT Service" in body
                    or "xml" in str(headers.get("Content-Type", "")).lower()
                )
            )
            success = bool(backend_alive and lighttpd_alive and probe and application_response)
            result = {
                "success": success,
                "backend": backend,
                "endpoint": endpoint,
                "runtime_repair": repair,
                "source_rootfs_modified": False,
                "backend_child": {
                    "started": backend_process.pid is not None,
                    "alive_after_startup": backend_alive,
                    "command": backend_command,
                    "listener": {"host": str(listener_host), "port": int(listener_port)},
                },
                "lighttpd": {
                    "started": lighttpd_process.pid is not None,
                    "alive_after_startup": lighttpd_alive,
                    "command": lighttpd_command,
                    "port": port,
                },
                "probe": probe,
                "request_observations": request_observations,
                "application_response_reached": application_response,
                "errors": errors,
                "diagnosis": "fastcgi_integration_reachable" if success else "fastcgi_validation_blocked",
            }
        except _FastCGIIntegrationBlocked:
            pass
        finally:
            for process in (lighttpd_process, backend_process):
                if process is not None and process.poll() is None:
                    _terminate_process_tree(process)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        _kill_process_tree(process)
            for handle in (backend_stdout, backend_stderr, lighttpd_stdout, lighttpd_stderr):
                handle.close()
            try:
                listener.close()
            except OSError:
                pass
        if result is None:
            result = {
                "success": False,
                "backend": backend,
                "endpoint": endpoint,
                "runtime_repair": repair,
                "source_rootfs_modified": False,
                "request_observations": request_observations,
                "application_response_reached": False,
                "errors": errors or ["FastCGI integration validation ended without a structured runtime result"],
                "diagnosis": "fastcgi_validation_inconclusive",
            }
        result["logs"] = {
            "backend_stderr": _tail(backend_stderr_path, 80),
            "lighttpd_stderr": _tail(lighttpd_stderr_path, 80),
        }
        save_application_json(app_dir / "integration_validation.json", result)
        return result

    def start_application_backend(
        self,
        backend: str = "device_manager",
        *,
        stability_seconds: int = 5,
    ) -> dict[str, Any]:
        prepared = self.prepare_service("lighttpd", force_reconstruct=True)
        if not prepared.get("success"):
            return prepared
        runtime_rootfs = Path(prepared["service_rootfs"])
        service_profile = ServiceLaunchProfile(**prepared["profile"])
        app_dir = self._application_dir(backend)
        stdout_path = app_dir / "logs" / "startup_stdout.log"
        stderr_path = app_dir / "logs" / "startup_stderr.log"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        command = self._service_command(runtime_rootfs, service_profile)
        env = dict(os.environ)
        env.update(service_profile.environment)
        stdout = stdout_path.open("wb")
        stderr = stderr_path.open("wb")
        start = time.monotonic()
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, cwd="/", env=env)
        except OSError as exc:
            stdout.close()
            stderr.close()
            return {"success": False, "errors": [str(exc)], "command": command}
        time.sleep(max(0, stability_seconds))
        exit_code = process.poll()
        duration = round(time.monotonic() - start, 3)
        if exit_code is None:
            socket_ready = _fastcgi_socket_ready(runtime_rootfs, backend)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            stdout.close()
            stderr.close()
            result = {
                "success": True,
                "backend": backend,
                "state": "running",
                "duration": duration,
                "command": command,
                "socket_ready": socket_ready,
            }
        else:
            stdout.close()
            stderr.close()
            stdout_text = _read_text(stdout_path)
            stderr_text = _read_text(stderr_path)
            dependencies = self.get_application_dependencies(backend)
            missing_dependencies = [
                item["path_or_name"]
                for item in dependencies.get("dependencies", [])
                if item.get("required") and not item.get("available")
            ]
            failure = ApplicationBackendFailure(
                backend=backend,
                binary=_application_binary(backend),
                exit_code=exit_code,
                signal=None,
                stdout_preview=stdout_text[:2000],
                stderr_preview=stderr_text[-4000:],
                runtime_duration=duration,
                dependencies=[item["path_or_name"] for item in dependencies.get("dependencies", [])],
                missing_dependencies=missing_dependencies,
                diagnosis=classify_application_failure(stderr_text, exit_code),
            )
            result = {"success": False, "backend": backend, "failure": failure.to_dict(), "command": command}
            save_application_json(app_dir / "failure.json", failure.to_dict())
        save_application_json(app_dir / "startup.json", result)
        return result

    def list_application_endpoints(self, backend: str = "device_manager") -> dict[str, Any]:
        rootfs = self._rootfs()
        if rootfs is None:
            return {"success": False, "errors": ["rootfs not available"]}
        profile = reconstruct_fastcgi_launch(rootfs, _application_binary(backend), self.runner)
        result = reconstruct_endpoints(rootfs, profile)
        result["backend"] = backend
        save_application_json(self._application_dir(backend) / "endpoints.json", result)
        return result

    def probe_application_endpoint(
        self,
        backend: str,
        endpoint: str,
        *,
        method: str = "GET",
        stability_seconds: int = 5,
    ) -> dict[str, Any]:
        endpoints = self.list_application_endpoints(backend)
        known = {item["path"]: item for item in endpoints.get("endpoints", [])}
        if endpoint not in known:
            return {"success": False, "errors": [f"endpoint was not reconstructed: {endpoint}"]}
        if method.upper() not in {"GET", "HEAD"}:
            return {"success": False, "errors": ["only benign GET/HEAD endpoint probes are allowed"]}
        startup = self.start_application_backend(backend, stability_seconds=stability_seconds)
        if not startup.get("success"):
            result = {
                "success": False,
                "backend": backend,
                "endpoint": endpoint,
                "diagnosis": "backend_blocked",
                "startup": startup,
            }
            save_application_json(self._application_dir(backend) / "endpoint_probe.json", result)
            return result
        url = f"https://127.0.0.1:3000{endpoint}"
        try:
            response = probe_http(url)
        except Exception as exc:  # noqa: BLE001 - structured probe failure
            result = {"success": False, "backend": backend, "endpoint": endpoint, "errors": [str(exc)], "startup": startup}
            save_application_json(self._application_dir(backend) / "endpoint_probe.json", result)
            return result
        result = {"success": True, "backend": backend, "endpoint": endpoint, "response": response, "startup": startup}
        save_application_json(self._application_dir(backend) / "endpoint_probe.json", result)
        return result

    def status(self) -> dict[str, Any]:
        return EmulationState(backend=self.name, status="stopped").to_dict()

    def stop(self) -> dict[str, Any]:
        for service in list(self.service_processes):
            self.stop_service(service)
        self.runner.run(["pkill", "-f", "qemu-arm-static"], timeout=10)
        return {"success": True}

    def logs(self, limit: int = 200) -> list[str]:
        return []

    def check_environment(self) -> dict[str, Any]:
        caps = detect_capabilities()
        return {
            "success": shutil.which("qemu-arm-static") is not None,
            "capabilities": caps.to_dict(),
        }

    def _rootfs(self) -> Path | None:
        report = self.workspace.load_report()
        extraction = report.get("extraction", {})
        canonical = extraction.get("canonical_rootfs") or {}
        candidates = [
            extraction.get("rootfs"),
            canonical.get("workspace_relative_path"),
            canonical.get("path"),
            canonical.get("host_path"),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            path = Path(str(candidate))
            if not path.is_absolute():
                path = self.workspace.task_dir / path
            if path.is_dir():
                return path
        return None

    def _service_dir(self, service: str) -> Path:
        path = self.workspace.dynamic_dir / "services" / service
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _load_or_reconstruct_profile(self, service: str, *, force_reconstruct: bool = False) -> ServiceLaunchProfile:
        path = self._service_dir(service) / "launch_profile.json"
        if path.exists() and not force_reconstruct:
            return ServiceLaunchProfile(**json.loads(path.read_text(encoding="utf-8")))
        rootfs = self._rootfs()
        if rootfs is None:
            raise ValueError("rootfs not available")
        return reconstruct_service_startup(rootfs, service)

    def _application_dir(self, backend: str) -> Path:
        path = self.workspace.dynamic_dir / "application" / backend
        path.mkdir(parents=True, exist_ok=True)
        (path / "logs").mkdir(parents=True, exist_ok=True)
        return path

    def _service_command(
        self,
        runtime_rootfs: Path,
        profile: ServiceLaunchProfile,
        *,
        qemu_args: list[str] | None = None,
    ) -> list[str]:
        if shutil.which("proot"):
            command = ["proot", "-R", str(runtime_rootfs)]
            for device in ("/dev/urandom", "/dev/random"):
                if Path(device).exists():
                    command.extend(["-b", f"{device}:{device}"])
            command.extend(["/usr/bin/qemu-arm-static", *(qemu_args or []), profile.binary, *profile.arguments])
            return command
        return [
            "chroot",
            str(runtime_rootfs),
            "/usr/bin/qemu-arm-static",
            *(qemu_args or []),
            profile.binary,
            *profile.arguments,
        ]

    def _backend_command(
        self,
        runtime_rootfs: Path,
        binary: str,
        *,
        qemu_args: list[str] | None = None,
        cwd: str | None = None,
    ) -> list[str]:
        if shutil.which("proot"):
            proot = shutil.which("proot") or "proot"
            command = [proot, "-R", str(runtime_rootfs)]
            if cwd:
                command.extend(["-w", cwd])
            for device in ("/dev/urandom", "/dev/random"):
                if Path(device).exists():
                    command.extend(["-b", f"{device}:{device}"])
            command.extend(["/usr/bin/qemu-arm-static", *(qemu_args or []), binary])
            return command
        return [
            "chroot",
            str(runtime_rootfs),
            "/usr/bin/qemu-arm-static",
            *(qemu_args or []),
            binary,
        ]


def create_backend(config: DynamicConfig, workspace: str | Path) -> EmulationBackend:
    caps = detect_capabilities()
    backend = config.backend.lower()
    if backend in {"service", "service-qemu", "qemu-user-service"}:
        return QemuUserServiceBackend(workspace)
    if backend in {"qemu", "docker-qemu"} or caps.compatible_backend:
        return DockerQemuBackend(workspace, config=config)
    if backend == "firmae" and caps.native_firmae:
        return FirmAEBackend(workspace)
    if backend == "firmae":
        return FirmAECompatBackend(workspace, config=config)
    if shutil.which("qemu-arm-static") is not None:
        return QemuUserServiceBackend(workspace)
    return QEMUBackend(workspace)


def _read_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Path):
        if not value.exists():
            return ""
        return value.read_text(encoding="utf-8", errors="replace")
    return str(value or "")


def _classify_boot(console: str, exit_code: int | None, timed_out: bool) -> tuple[str, list[str]]:
    lowered = console.lower()
    if (
        "unable to mount root" in lowered
        or "vfs: unable to mount root" in lowered
        or "no filesystem could mount root" in lowered
        or "couldn't mount because of unsupported optional features" in lowered
    ):
        return "rootfs_mount_failure", ["Root filesystem mount failed"]
    if "kernel panic" in lowered:
        return "kernel_boot_failure", ["Kernel panic observed in serial console"]
    if "no working init found" in lowered:
        return "init_failure", ["No working init found"]
    if "rebooting" in lowered:
        return "boot_timeout", ["Guest rebooted without completing boot"]
    if timed_out:
        return "boot_timeout", ["QEMU guest did not complete boot before timeout"]
    if exit_code not in (None, 0):
        return "kernel_boot_failure", [f"QEMU exited with code {exit_code}"]
    return "boot_timeout", ["No boot completion marker observed"]


def _tail(path: Path, lines: int) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]


def _replace_config_argument(arguments: list[str], config_file: str) -> list[str]:
    updated = list(arguments)
    for index, argument in enumerate(updated[:-1]):
        if argument == "-f":
            updated[index + 1] = config_file
            return updated
    return [*updated, "-f", config_file]


class _FastCGIIntegrationBlocked(Exception):
    pass


def _fastcgi_integration_blocked_result(
    *,
    backend: str,
    endpoint: str,
    repair: dict[str, Any],
    backend_command: list[str],
    listener_host: str,
    listener_port: int,
    errors: list[str],
    blocked_reason: str,
    lighttpd_command: list[str] | None = None,
    backend_alive: bool = False,
) -> dict[str, Any]:
    return {
        "success": False,
        "backend": backend,
        "endpoint": endpoint,
        "runtime_repair": repair,
        "source_rootfs_modified": False,
        "runtime_environment_blocked": True,
        "blocked_reason": blocked_reason,
        "backend_child": {
            "started": False,
            "alive_after_startup": backend_alive,
            "command": backend_command,
            "listener": {"host": listener_host, "port": listener_port},
        },
        "lighttpd": {
            "started": False,
            "alive_after_startup": False,
            "command": lighttpd_command or [],
        },
        "probe": None,
        "request_observations": [],
        "application_response_reached": False,
        "errors": list(errors),
        "diagnosis": "RUNTIME_ENVIRONMENT_BLOCKED",
    }


def _lighttpd_without_fastcgi(config: str) -> str:
    output = []
    skipping_fastcgi_server = False
    depth = 0
    for line in config.splitlines():
        stripped = line.strip()
        if skipping_fastcgi_server:
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                skipping_fastcgi_server = False
            continue
        if '"mod_fastcgi"' in line:
            continue
        if stripped.startswith("fastcgi.debug"):
            continue
        if stripped.startswith("fastcgi.server"):
            depth = line.count("(") - line.count(")")
            skipping_fastcgi_server = depth > 0
            continue
        output.append(line)
    return "\n".join(output) + "\n"


def _lighttpd_external_fastcgi(
    config: str,
    *,
    endpoint: str,
    socket_guest: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> str:
    output = []
    skipping_fastcgi_server = False
    depth = 0
    saw_fastcgi_module = False
    for line in config.splitlines():
        stripped = line.strip()
        if '"mod_fastcgi"' in line:
            saw_fastcgi_module = True
        if skipping_fastcgi_server:
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                skipping_fastcgi_server = False
            continue
        if stripped.startswith("fastcgi.debug"):
            continue
        if stripped.startswith("fastcgi.server"):
            depth = line.count("(") - line.count(")")
            skipping_fastcgi_server = depth > 0
            continue
        output.append(line)
    if not saw_fastcgi_module:
        output.append('server.modules += ( "mod_fastcgi" )')
    output.extend(
        [
            "",
            "# DeepDuck Round 3.5 runtime reconstruction: external FastCGI child parity.",
            "fastcgi.server = (",
            f'  "{endpoint}" => ((',
        ]
    )
    if socket_guest:
        output.append(f'    "socket" => "{socket_guest}",')
    else:
        output.append(f'    "host" => "{host or "127.0.0.1"}",')
        output.append(f'    "port" => {int(port or 9000)},')
    output.extend(
        [
            '    "check-local" => "disable",',
            '    "max-procs" => 1',
            "  ))",
            ")",
            "",
        ]
    )
    return "\n".join(output) + "\n"


def _application_binary(backend: str) -> str:
    if backend in {"device_manager", "device_manager.fcgi"}:
        return "/www/services/device_manager/device_manager.fcgi"
    if backend.startswith("/"):
        return backend
    return f"/www/services/{backend}/{backend}.fcgi"


def infer_context_from_dict(data: dict[str, Any]) -> FastCGIProcessContext:
    return FastCGIProcessContext(
        argv=list(data.get("argv") or []),
        environment=dict(data.get("environment") or {}),
        cwd=str(data.get("cwd") or "/"),
        uid=data.get("uid"),
        gid=data.get("gid"),
        stdin_fd=dict(data.get("stdin_fd") or {}),
        stdout_fd=dict(data.get("stdout_fd") or {}),
        stderr_fd=dict(data.get("stderr_fd") or {}),
        open_fds=list(data.get("open_fds") or []),
        listen_socket_fd=data.get("listen_socket_fd"),
        parent_pid=data.get("parent_pid"),
        process_group=data.get("process_group"),
    )


def infer_runtime_snapshot_from_dict(data: dict[str, Any]) -> FastCGIRuntimeSnapshot:
    return FastCGIRuntimeSnapshot(
        mode=str(data.get("mode") or "unknown"),
        backend=str(data.get("backend") or "device_manager"),
        executable=str(data.get("executable") or ""),
        argv=list(data.get("argv") or []),
        cwd=str(data.get("cwd") or "/"),
        uid=data.get("uid"),
        gid=data.get("gid"),
        supplementary_groups=list(data.get("supplementary_groups") or []),
        environment=dict(data.get("environment") or {}),
        stdin=dict(data.get("stdin") or {}),
        stdout=dict(data.get("stdout") or {}),
        stderr=dict(data.get("stderr") or {}),
        open_fds=list(data.get("open_fds") or []),
        fastcgi_listener_fd=data.get("fastcgi_listener_fd"),
        socket_type=data.get("socket_type"),
        socket_address=data.get("socket_address"),
        filesystem_root=data.get("filesystem_root"),
        writable_directories=list(data.get("writable_directories") or []),
        required_files=list(data.get("required_files") or []),
        config_files=list(data.get("config_files") or []),
        nvram_dependencies=list(data.get("nvram_dependencies") or []),
        parent_process=dict(data.get("parent_process") or {}),
        process_hierarchy=list(data.get("process_hierarchy") or []),
        resource_limits=dict(data.get("resource_limits") or {}),
        signal_state=dict(data.get("signal_state") or {}),
        loader=data.get("loader"),
        shared_libraries=list(data.get("shared_libraries") or []),
        file_access=list(data.get("file_access") or []),
        qemu_user_args=list(data.get("qemu_user_args") or []),
        proot_args=list(data.get("proot_args") or []),
        runtime_repair_ids=list(data.get("runtime_repair_ids") or []),
        observations=dict(data.get("observations") or {}),
    )


def infer_runtime_diff_from_dict(data: dict[str, Any]) -> FastCGIRuntimeDiff:
    return FastCGIRuntimeDiff(
        backend=str(data.get("backend") or "device_manager"),
        differences=[
            FastCGIRuntimeDifference(
                field=str(item.get("field") or ""),
                standalone_value=item.get("standalone_value"),
                lighttpd_value=item.get("lighttpd_value"),
                severity=str(item.get("severity") or "low"),
                possible_relevance=str(item.get("possible_relevance") or ""),
                confidence=float(item.get("confidence", 0.5)),
            )
            for item in data.get("differences", [])
            if isinstance(item, dict)
        ],
        summary=dict(data.get("summary") or {}),
    )


def _minimal_firmware_env() -> dict[str, str]:
    return {
        "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
        "LD_LIBRARY_PATH": "/lib:/usr/lib",
    }


def _fastcgi_socket_ready(runtime_rootfs: Path, backend: str) -> bool:
    tmp = runtime_rootfs / "tmp"
    if not tmp.exists():
        return False
    if backend == "device_manager":
        return any(tmp.glob("device_manager-*.socket*"))
    return any(tmp.glob("*.socket*"))


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGTERM)
            return
        except OSError:
            pass
    process.terminate()


def _kill_process_tree(process: subprocess.Popen) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except OSError:
            pass
    process.kill()
