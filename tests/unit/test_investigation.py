from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwagent.config import AgentSettings, GhidraSettings, Round2Config
from fwagent.investigation import StaticInvestigator
from fwagent.models import Evidence, Hypothesis
from tests.unit.test_ghidra_api import write_fake_x86_elf


class InvestigationTests(unittest.TestCase):
    def test_evidence_and_hypothesis_serialize(self) -> None:
        evidence = Evidence(
            id="E-0001",
            type="function_call",
            binary="/bin/app",
            function="main",
            address="0x1",
            description="calls system",
            source_tool="ghidra",
            confidence=1.0,
        )
        hypothesis = Hypothesis(
            id="H-0001",
            title="candidate",
            cwe="CWE-78",
            status="candidate",
            confidence=0.2,
            evidence_ids=[evidence.id],
        )

        self.assertEqual(evidence.to_dict()["id"], "E-0001")
        self.assertEqual(hypothesis.to_dict()["status"], "candidate")

    def test_investigation_respects_step_limit_and_saves_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            task = workspace / "task"
            rootfs = task / "rootfs"
            binary = rootfs / "bin" / "app"
            binary.parent.mkdir(parents=True)
            (task / "reports").mkdir(parents=True)
            write_fake_x86_elf(binary, b"/bin/sh\x00")
            (task / "reports" / "analysis.json").write_text(
                json.dumps(
                    {
                        "extraction": {"rootfs": str(rootfs)},
                        "priority_binaries": [{"path": "/bin/app", "score": 50, "reasons": ["test"]}],
                    }
                ),
                encoding="utf-8",
            )
            config = Round2Config(
                ghidra=GhidraSettings(home=Path("missing"), minimum_priority_score=30),
                agent=AgentSettings(max_steps=1, max_binary_analyses=1),
            )

            result = StaticInvestigator(workspace, "task", config=config).run()

            self.assertEqual(result["steps"], 1)
            self.assertTrue((task / "evidence" / "evidence.json").exists())
            self.assertTrue((task / "hypotheses" / "hypotheses.json").exists())
            self.assertTrue((task / "reports" / "investigation.json").exists())


if __name__ == "__main__":
    unittest.main()

