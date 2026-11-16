"""Offline tests for discovery: secret scanning, spec summaries, SSRF in js_recon."""

import asyncio
import unittest

from osint_mcp import discovery_tools


class SecretScanTests(unittest.TestCase):
    def test_aws_key_detected(self):
        text = 'var cfg = {key: "AKIAIOSFODNN7EXAMPLE"};'
        scan = discovery_tools._scan_js(text)
        types = [item["type"] for item in scan["secrets"]]
        self.assertIn("aws_access_key", types)
        value = next(item for item in scan["secrets"] if item["type"] == "aws_access_key")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", value["value"])  # masked
        self.assertTrue(value["value"].startswith("AKIA"))

    def test_private_key_detected(self):
        scan = discovery_tools._scan_js("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
        self.assertIn("private_key_block", [item["type"] for item in scan["secrets"]])

    def test_openai_and_slack(self):
        text = 'const k1 = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX";\nconst k2 = "xoxb-123456789-abcdef";'
        scan = discovery_tools._scan_js(text)
        types = {item["type"] for item in scan["secrets"]}
        self.assertIn("openai_key", types)
        self.assertIn("slack_token", types)

    def test_endpoints_and_sourcemaps(self):
        text = "fetch('/api/v2/users');\n//# sourceMappingURL=app.min.js.map"
        scan = discovery_tools._scan_js(text)
        self.assertIn("/api/v2/users", scan["endpoints"])
        self.assertIn("app.min.js.map", scan["source_maps"])

    def test_generic_assignment_not_flagged_for_literals(self):
        scan = discovery_tools._scan_js("const token = 'undefined';")
        self.assertEqual(scan["secrets"], [])


class SpecSummaryTests(unittest.TestCase):
    def test_openapi_summary(self):
        spec = {
            "openapi": "3.1.0",
            "info": {"title": "API", "version": "2.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/items": {"delete": {}},
            },
            "components": {"securitySchemes": {"bearer": {"type": "http"}}},
        }
        summary = discovery_tools._spec_summary(spec)
        self.assertEqual(summary["title"], "API")
        self.assertEqual(summary["path_count"], 2)
        self.assertIn("get", summary["http_methods"])
        self.assertEqual(summary["servers"], ["https://api.example.com"])
        self.assertTrue(summary["has_auth"])

    def test_legacy_swagger_version(self):
        summary = discovery_tools._spec_summary({"swagger": "2.0", "paths": {}})
        self.assertEqual(summary["spec_version"], "2.0")


class JsReconGuardTests(unittest.TestCase):
    def test_js_recon_blocks_private_url(self):
        result = asyncio.run(discovery_tools.js_recon("http://127.0.0.1/app.js"))
        self.assertFalse(result.get("ok", True))
        self.assertIn("blocked", str(result.get("error", "")).lower())


if __name__ == "__main__":
    unittest.main()
