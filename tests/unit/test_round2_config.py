from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.config import load_round2_config


class Round2ConfigTests(unittest.TestCase):
    def test_loads_default_ghidra_config(self) -> None:
        config = load_round2_config()

        self.assertEqual(config.ghidra.timeout_seconds, 300)
        self.assertEqual(config.ghidra.max_binary_size_mb, 100)
        self.assertEqual(config.ghidra.minimum_priority_score, 30)
        self.assertFalse(config.runtime.network)
        self.assertEqual(config.agent.max_steps, 30)

    def test_loads_nested_yaml_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ghidra.yaml"
            path.write_text(
                "\n".join(
                    [
                        "ghidra:",
                        "  analysis:",
                        "    timeout_seconds: 12",
                        "  scheduling:",
                        "    minimum_priority_score: 42",
                        "agent:",
                        "  max_steps: 3",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_round2_config(path)

            self.assertEqual(config.ghidra.timeout_seconds, 12)
            self.assertEqual(config.ghidra.minimum_priority_score, 42)
            self.assertEqual(config.agent.max_steps, 3)


if __name__ == "__main__":
    unittest.main()

