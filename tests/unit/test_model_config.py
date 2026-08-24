from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.model.config import ModelConfigError, load_model_config


class ModelConfigTests(unittest.TestCase):
    def test_loads_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MODEL_PROVIDER": "TestProvider",
                "MODEL_NAME": "test-model",
                "MODEL_API_KEY": "sk-test-key",
                "MODEL_BASE_URL": "https://example.com",
            },
            clear=True,
        ):
            config = load_model_config(env_path="missing.env")

        self.assertEqual(config.provider, "TestProvider")
        self.assertEqual(config.model, "test-model")
        self.assertEqual(config.api_key, "sk-test-key")
        self.assertEqual(config.base_url, "https://example.com")

    def test_loads_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "MODEL_PROVIDER=DotEnv",
                        "MODEL_NAME=dot-model",
                        "MODEL_API_KEY=sk-dotenv",
                        "MODEL_BASE_URL=https://dot.example",
                    ]
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                config = load_model_config(env_path=env_path)

            self.assertEqual(config.provider, "DotEnv")
            self.assertEqual(config.model, "dot-model")
            self.assertEqual(config.api_key, "sk-dotenv")
            self.assertEqual(config.base_url, "https://dot.example")

    def test_missing_key_raises_clear_error(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = load_model_config(env_path="missing.env")
            with self.assertRaises(ModelConfigError) as caught:
                config.require_credentials()

        self.assertIn("Model API credentials are not configured.", str(caught.exception))

    def test_safe_dict_never_contains_key(self) -> None:
        config = load_model_config(env_path="missing.env")
        config = config.__class__(
            provider="P",
            model="M",
            api_key="sk-secret",
            base_url="https://example.com",
        )
        safe = config.safe_dict()

        self.assertNotIn("api_key", safe)
        self.assertTrue(safe["api_key_present"])


if __name__ == "__main__":
    unittest.main()
