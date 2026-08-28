from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.backend import QemuUserServiceBackend
from fwagent.dynamic.models import DynamicEvidence, is_canonical_runtime_evidence
from fwagent.dynamic.service import (
    classify_runtime_trace,
    RuntimeRepair,
    ServiceLaunchProfile,
    assess_service_runtime_feasibility,
    repeated_failure_stop_reason,
    resolve_runtime_rootfs,
    resolve_user_runtime_mapping,
)
from fwagent.reporting.final_report import ReportGenerator


class _Result:
    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0, timed_out: bool = False):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out


class _ReadelfRunner:
    def __init__(self, *, interpreter: str = "/lib/ld-uClibc.so.0", libraries: tuple[str, ...] = ("libc.so.0",)):
        self.interpreter = interpreter
        self.libraries = libraries

    def run(self, command, timeout=10, **kwargs):
        if "-l" in command:
            return _Result(f"[Requesting program interpreter: {self.interpreter}]\n")
        return _Result("\n".join(f"(NEEDED) Shared library: [{item}]" for item in self.libraries))


class V01DynamicHardeningTests(unittest.TestCase):
    def test_mips_little_endian_runtime_mapping(self) -> None:
        mapping = resolve_user_runtime_mapping("mips", "little")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.emulator, "qemu-mipsel-static")
        self.assertEqual(mapping.system_emulator, "qemu-system-mipsel")

    def test_mips_big_endian_runtime_mapping(self) -> None:
        mapping = resolve_user_runtime_mapping("mips", "big")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.emulator, "qemu-mips-static")
        self.assertEqual(mapping.system_emulator, "qemu-system-mips")

    def test_backend_detects_emulator_for_rootfs_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "task"
            (task / "reports").mkdir(parents=True)
            (task / "artifacts").mkdir()
            rootfs = task / "rootfs"
            rootfs.mkdir()
            (task / "reports" / "analysis.json").write_text(json.dumps({"platform": {"architecture": "mips", "endianness": "big"}}), encoding="utf-8")
            (task / "artifacts" / "rootfs.json").write_text(json.dumps({"canonical": True, "canonical_linux_rootfs": str(rootfs), "linux_semantics_preserved": True, "architecture": "mips", "endianness": "big"}), encoding="utf-8")
            backend = QemuUserServiceBackend(task)
            with patch("fwagent.dynamic.backend.shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name == "qemu-mips-static" else None):
                environment = backend.check_environment()
            self.assertTrue(environment["success"])
            self.assertEqual(environment["runtime_mapping"]["emulator"], "qemu-mips-static")

    def test_loader_resolution_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp)
            (rootfs / "bin").mkdir()
            (rootfs / "bin" / "svc").write_bytes(b"\x7fELF")
            (rootfs / "lib").mkdir()
            (rootfs / "lib" / "libc.so.0").write_bytes(b"lib")
            profile = ServiceLaunchProfile("/bin/svc", [], service="svc", required_paths=["/bin/svc"])
            with patch("fwagent.dynamic.service.shutil.which", return_value="/usr/bin/qemu-mipsel-static"):
                assessment = assess_service_runtime_feasibility(rootfs, profile, architecture="mips", endianness="little", runner=_ReadelfRunner())
            self.assertFalse(assessment.runtime_feasible)
            self.assertEqual(assessment.loader, "/lib/ld-uClibc.so.0")
            self.assertEqual(assessment.failure_category, "loader_missing")

    def test_canonical_linux_rootfs_is_preferred_for_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp)
            canonical = task / "canonical"
            host_safe = task / "host-safe"
            canonical.mkdir()
            host_safe.mkdir()
            (task / "artifacts").mkdir()
            (task / "artifacts" / "rootfs.json").write_text(json.dumps({"canonical": True, "canonical_linux_rootfs": str(canonical), "host_safe_view": str(host_safe), "linux_semantics_preserved": True, "semantic_fidelity": "canonical-linux-rootfs"}), encoding="utf-8")
            result = resolve_runtime_rootfs(task)
            self.assertEqual(Path(result["path"]), canonical)
            self.assertFalse(result["degraded_provenance"])

    def test_host_safe_view_is_not_silently_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp)
            host_safe = task / "host-safe"
            host_safe.mkdir()
            (task / "artifacts").mkdir()
            (task / "artifacts" / "rootfs.json").write_text(json.dumps({"canonical": True, "host_safe_view": str(host_safe), "linux_semantics_preserved": False, "semantic_fidelity": "host-safe-view"}), encoding="utf-8")
            result = resolve_runtime_rootfs(task)
            self.assertTrue(result["degraded_provenance"])
            self.assertEqual(result["source_field"], "host_safe_view")

    def test_structured_runtime_blocker_has_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp)
            profile = ServiceLaunchProfile("/bin/missing", [], service="missing", required_paths=["/bin/missing"])
            with patch("fwagent.dynamic.service.shutil.which", return_value=None):
                assessment = assess_service_runtime_feasibility(rootfs, profile, architecture="mips", endianness="little")
            data = assessment.to_dict()
            self.assertFalse(data["runtime_feasible"])
            self.assertEqual(data["failure_category"], "emulator_unavailable")
            self.assertTrue(data["blocking_reasons"])
            for field in ("service", "binary", "runtime_candidate", "selected_backend", "selection_reason"):
                self.assertIn(field, data)

    def test_process_started_real_provenance_is_canonical(self) -> None:
        evidence = DynamicEvidence("DE-PROC", "process_started", "process loaded", "runtime", 0.9)
        self.assertTrue(is_canonical_runtime_evidence(evidence))

    def test_response_observed_real_provenance_is_canonical(self) -> None:
        evidence = DynamicEvidence("DE-RESP", "protocol_response", "protocol replied", "runtime", 0.9)
        self.assertTrue(is_canonical_runtime_evidence(evidence))

    def test_attempted_is_not_observed(self) -> None:
        evidence = DynamicEvidence("DE-PLAN", "validation_plan_created", "plan", "planner", 0.9)
        self.assertFalse(is_canonical_runtime_evidence(evidence))

    def test_blocked_is_not_real(self) -> None:
        evidence = DynamicEvidence("DE-BLOCK", "validation_blocked", "blocked", "runtime", 0.9)
        self.assertFalse(is_canonical_runtime_evidence(evidence))

    def test_mock_is_not_real(self) -> None:
        evidence = DynamicEvidence("MDE-X", "process_started", "mock", "mock", 0.9, provenance="mock", execution_mode="mock", runtime_observation_real=False)
        self.assertFalse(is_canonical_runtime_evidence(evidence))

    def test_model_evidence_creator_cannot_self_assign_canonical_runtime_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "task"
            backend = QemuUserServiceBackend(task)
            api = DynamicToolAPI(tmp, "task", backend=backend)
            api._create_evidence(
                {
                    "type": "process_started",
                    "observation": "provider assertion only",
                    "source_tool": "dynamic.create_evidence",
                }
            )
            self.assertFalse(is_canonical_runtime_evidence(api.evidence[-1]))
            api._create_evidence(
                {
                    "type": "protocol_response",
                    "observation": "internally recorded controlled response",
                    "source_tool": "dynamic.run_safe_validation",
                },
                canonical_runtime_observation=True,
            )
            self.assertTrue(is_canonical_runtime_evidence(api.evidence[-1]))

    def test_runtime_repair_metadata_is_complete(self) -> None:
        repair = RuntimeRepair("RR-X", "create_writable_directory", "/var/run", "runtime lifecycle", files_modified=["/var/run"], original_environment_gap="path absent", fidelity_limitations=["vendor init not run"])
        data = repair.to_dict()
        for field in ("original_environment_gap", "files_modified", "source_rootfs_modified", "runtime_copy_modified", "transport_changes", "environment_changes", "original_startup_confirmed", "fidelity_limitations"):
            self.assertIn(field, data)
        self.assertFalse(data["source_rootfs_modified"])

    def test_repeated_failure_fingerprint_stops(self) -> None:
        attempts = [{"failure_fingerprint": "same"}, {"failure_fingerprint": "same"}]
        self.assertEqual(repeated_failure_stop_reason(attempts), "same_failure_fingerprint_repeated")

    def test_unix_socket_dependency_is_classified_from_syscall_trace(self) -> None:
        category, reason = classify_runtime_trace(
            "12 socket(PF_UNIX,SOCK_STREAM,IPPROTO_IP) = 3\n"
            "12 connect(3,0x12345678,110) = -1 errno=2 (No such file or directory)\n",
            0,
        )
        self.assertEqual(category, "unix_socket_dependency_missing")
        self.assertIn("vendor IPC endpoint", reason)

    def test_report_exposes_dynamic_coverage_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "task"
            (task / "reports").mkdir(parents=True)
            (task / "dynamic" / "evidence").mkdir(parents=True)
            (task / "reports" / "analysis.json").write_text(json.dumps({"firmware": {"filename": "fw.bin"}}), encoding="utf-8")
            (task / "dynamic" / "runtime_summary.json").write_text(json.dumps({"dynamic_feasibility": "PARTIAL", "process_started": True, "service_reachable": False, "request_sent": False, "response_observed": False}), encoding="utf-8")
            evidence = DynamicEvidence("DE-PROC", "process_started", "loaded", "runtime", 0.9)
            (task / "dynamic" / "evidence" / "evidence.json").write_text(json.dumps([evidence.to_dict()]), encoding="utf-8")
            model = ReportGenerator(tmp, "task").build_model()
            self.assertEqual(model.validation["runtime"]["dynamic_feasibility"], "PARTIAL")
            self.assertEqual(model.evidence_summary["real_dynamic"], 1)

    def test_tplink_fastcgi_observation_semantics_remain_real(self) -> None:
        evidence = DynamicEvidence("DE-FCGI", "fastcgi_application_response", "application response", "fastcgi", 0.9)
        self.assertTrue(is_canonical_runtime_evidence(evidence))


if __name__ == "__main__":
    unittest.main()
