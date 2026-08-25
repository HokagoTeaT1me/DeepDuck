from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = REPO_ROOT / "workspace"
FIRMWARE = WORKSPACE / "provided-firmware-zip" / "tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin"


def enabled(name: str) -> bool:
    return os.environ.get(name) == "1"


class DeepDuckV01RealStaticAcceptanceTests(unittest.TestCase):
    @unittest.skipUnless(enabled("DEEPDUCK_RUN_REAL_DOCKER_TESTS"), "set DEEPDUCK_RUN_REAL_DOCKER_TESTS=1 to run real Docker extraction acceptance")
    def test_fresh_docker_extraction_establishes_canonical_rootfs(self) -> None:
        self.assertTrue(FIRMWARE.exists(), f"firmware missing: {FIRMWARE}")
        task_id = os.environ.get("DEEPDUCK_REAL_DOCKER_TASK_ID", "v0_1-real-docker-test")
        task_dir = WORKSPACE / task_id
        if task_dir.exists():
            shutil.rmtree(task_dir)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "fwagent.cli",
                "analyze",
                str(FIRMWARE),
                "--workspace",
                str(WORKSPACE),
                "--task-id",
                task_id,
                "--no-dynamic",
                "--timeout",
                os.environ.get("DEEPDUCK_REAL_DOCKER_TIMEOUT", "900"),
                "--json",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=int(os.environ.get("DEEPDUCK_REAL_DOCKER_TEST_TIMEOUT", "1200")),
        )
        self.assertIn(completed.returncode, {0, 1}, completed.stderr + completed.stdout)

        rootfs_path = task_dir / "artifacts" / "rootfs.json"
        extraction_path = task_dir / "artifacts" / "extraction.json"
        self.assertTrue(rootfs_path.exists(), completed.stdout + completed.stderr)
        self.assertTrue(extraction_path.exists())
        rootfs = json.loads(rootfs_path.read_text(encoding="utf-8"))
        extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
        attempts = extraction.get("attempts") or []

        self.assertTrue(rootfs.get("canonical"))
        self.assertTrue(rootfs.get("validated"))
        self.assertNotEqual(rootfs.get("source"), "imported")
        self.assertEqual(rootfs.get("extraction_method"), "docker-binwalk")
        self.assertGreater(rootfs.get("file_count", 0), 1000)
        self.assertGreater(rootfs.get("elf_count", 0), 100)
        self.assertTrue(any(item.get("method") == "docker-binwalk" and item.get("status") == "success" for item in attempts))

    @unittest.skipUnless(
        enabled("DEEPDUCK_RUN_REAL_DOCKER_TESTS") and enabled("DEEPDUCK_RUN_REAL_GHIDRA_TESTS"),
        "set DEEPDUCK_RUN_REAL_DOCKER_TESTS=1 and DEEPDUCK_RUN_REAL_GHIDRA_TESTS=1; Ghidra is checked inside the Docker worker",
    )
    def test_fresh_pipeline_produces_real_ghidra_evidence(self) -> None:
        self.assertTrue(FIRMWARE.exists(), f"firmware missing: {FIRMWARE}")
        task_id = os.environ.get("DEEPDUCK_REAL_GHIDRA_TASK_ID", "v0_1-real-ghidra-test")
        task_dir = WORKSPACE / task_id
        if task_dir.exists():
            shutil.rmtree(task_dir)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "fwagent.cli",
                "analyze",
                str(FIRMWARE),
                "--workspace",
                str(WORKSPACE),
                "--task-id",
                task_id,
                "--no-dynamic",
                "--timeout",
                os.environ.get("DEEPDUCK_REAL_GHIDRA_TIMEOUT", "1800"),
                "--json",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=int(os.environ.get("DEEPDUCK_REAL_GHIDRA_TEST_TIMEOUT", "2400")),
        )
        self.assertIn(completed.returncode, {0, 1}, completed.stderr + completed.stdout)

        summary_path = task_dir / "pipeline_summary.json"
        ghidra_path = task_dir / "ghidra" / "analysis_summary.json"
        evidence_path = task_dir / "dynamic" / "evidence" / "evidence.json"
        self.assertTrue(summary_path.exists(), completed.stdout + completed.stderr)
        self.assertTrue(ghidra_path.exists())
        self.assertTrue(evidence_path.exists())

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        ghidra = json.loads(ghidra_path.read_text(encoding="utf-8"))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        real_items = [
            item
            for item in ghidra.get("analyses", [])
            if item.get("success") and not (((item.get("result") or {}).get("metadata") or {}).get("fallback"))
        ]
        ghidra_evidence_ids = [item.get("id") for item in evidence if str(item.get("source", "")).lower().startswith("ghidra") or "GHIDRA" in str(item.get("id", ""))]

        self.assertGreater(summary.get("coverage", {}).get("ghidra_targets_scheduled", 0), 0)
        self.assertGreater(ghidra.get("real_ghidra_count", 0), 0)
        self.assertGreater(len(real_items), 0)
        self.assertGreater(len(ghidra_evidence_ids), 0)
        self.assertGreater(summary.get("coverage", {}).get("component_count", 0) + summary.get("coverage", {}).get("candidate_taint_paths", 0) + summary.get("coverage", {}).get("hypothesis_candidates", 0), 0)


if __name__ == "__main__":
    unittest.main()
