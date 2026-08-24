from __future__ import annotations

import unittest

from fwagent.model.redaction import redact_text, redact_value


class RedactionTests(unittest.TestCase):
    def test_redacts_exact_key(self) -> None:
        key = "sk-1234567890abcdef1234567890abcdef"
        text = f"key={key} Authorization: Bearer {key}"

        redacted = redact_text(text, [key])

        self.assertNotIn(key, redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_redacts_sk_and_bearer_patterns(self) -> None:
        text = "token=sk-abcdefghijklmnop Authorization: Bearer abc.def.ghi"

        redacted = redact_text(text)

        self.assertNotIn("sk-abcdefghijklmnop", redacted)
        self.assertNotIn("Bearer abc.def.ghi", redacted)

    def test_redact_value_recurses(self) -> None:
        key = "sk-secret-token"
        value = {"nested": [{"api_key": key, "safe": "ok"}]}

        redacted = redact_value(value, [key])

        self.assertEqual(redacted["nested"][0]["api_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"][0]["safe"], "ok")


if __name__ == "__main__":
    unittest.main()
