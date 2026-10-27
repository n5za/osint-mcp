"""Regression coverage for malformed local API key stores."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_mcp import common


class APIKeyStoreTests(unittest.TestCase):
    def test_non_object_json_is_treated_as_missing_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text('["unexpected"]', encoding="utf-8")
            with patch.object(common, "KEYS_PATH", str(path)):
                self.assertIsNone(common.api_key("test_store_regression_key"))

    def test_blank_environment_key_uses_stored_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text('{"test_blank_key": "stored-value"}', encoding="utf-8")
            with patch.object(common, "KEYS_PATH", str(path)):
                with patch.dict("os.environ", {"TEST_BLANK_KEY_API_KEY": "   "}):
                    self.assertEqual(common.api_key("test_blank_key"), "stored-value")

    def test_blank_stored_key_falls_back_to_next_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text('{"test_empty_key": "  ", "test_valid_key": "value"}', encoding="utf-8")
            with patch.object(common, "KEYS_PATH", str(path)):
                self.assertEqual(common.api_key("test_empty_key", "test_valid_key"), "value")


if __name__ == "__main__":
    unittest.main()
