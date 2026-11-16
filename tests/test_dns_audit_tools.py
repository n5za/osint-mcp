"""Offline behavior checks for the new passive DNS tools."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from osint_mcp import dns_audit_tools as audit


class DnsAuditTests(unittest.TestCase):
    def test_dnssec_signed(self):
        with patch.object(audit, "_records", new=AsyncMock(side_effect=[(["DS"], None), (["KEY"], None)])):
            result = asyncio.run(audit.dnssec_status("Example.com"))
        self.assertEqual(result["status"], "signed")
        self.assertFalse(result["validation_performed"])

    def test_dnssec_error_is_not_unsigned(self):
        with patch.object(audit, "_records", new=AsyncMock(side_effect=[([], "timeout"), ([], None)])):
            result = asyncio.run(audit.dnssec_status("example.com"))
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["ok"])

    def test_resolver_mismatch(self):
        answers = [
            {"provider": "cloudflare", "status": 0, "answers": ["192.0.2.1"]},
            {"provider": "google", "status": 0, "answers": ["192.0.2.2"]},
        ]
        with patch.object(audit, "_doh", new=AsyncMock(side_effect=answers)):
            result = asyncio.run(audit.dns_resolver_compare("example.com"))
        self.assertTrue(result["ok"])
        self.assertFalse(result["same_answers"])

    def test_reject_ip(self):
        result = asyncio.run(audit.dnssec_status("127.0.0.1"))
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
