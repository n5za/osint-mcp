"""Offline tests for DNS tooling: wordlist, permutations, port parsing, IP helpers."""

import asyncio
import os
import tempfile
import unittest

from osint_mcp import dns_tools, ip_tools


class WordlistTests(unittest.TestCase):
    def test_builtin_wordlist_expanded(self):
        words = dns_tools._load_wordlist("")
        self.assertGreaterEqual(len(words), 1000, "wordlist should be 1000+ entries")
        self.assertIn("kubernetes", words)
        self.assertEqual(words, sorted(set(words), key=str.lower))

    def test_custom_inline_wordlist(self):
        words = dns_tools._load_wordlist("alpha, beta gamma")
        self.assertEqual(words, ["alpha", "beta", "gamma"])

    def test_custom_file_wordlist(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("#comment\nfoo\nbar\n")
            path = handle.name
        try:
            words = dns_tools._load_wordlist(path)
            self.assertEqual(words, ["foo", "bar"])
        finally:
            os.unlink(path)

    def test_permutation_expansion(self):
        words = dns_tools._load_wordlist("api,admin")
        expanded = dns_tools._expand_permutations(words, limit=3000)
        self.assertIn("api-dev", expanded)
        self.assertIn("dev-api", expanded)
        self.assertIn("api2", expanded)
        self.assertIn("api-v2", expanded)
        self.assertLessEqual(len(expanded), 3000)


class PortParseTests(unittest.TestCase):
    def test_presets(self):
        self.assertEqual(ip_tools._parse_ports("top20"), ip_tools.TOP_20)
        self.assertEqual(ip_tools._parse_ports("web"), ip_tools.WEB_PORTS)

    def test_ranges_and_single(self):
        ports = ip_tools._parse_ports("80,443,8000-8003")
        self.assertEqual(ports, [80, 443, 8000, 8001, 8002, 8003])

    def test_reversed_range_and_bounds(self):
        ports = ip_tools._parse_ports("9-7,0,70000,443")
        self.assertEqual(ports, [7, 8, 9, 443])

    def test_invalid_spec_returns_empty(self):
        ports = ip_tools._parse_ports("abc,,")
        self.assertEqual(ports, [])


class TlsCertTests(unittest.TestCase):
    def test_tls_grab_against_local_server_is_none_on_refused(self):
        # nothing listens there; probe must return None, not raise
        result = ip_tools._grab_tls_cert_sync("127.0.0.1", 1, 0.3)
        self.assertIsNone(result)

    def test_port_service_mapping(self):
        self.assertEqual(ip_tools.port_service(443), "https")
        self.assertEqual(ip_tools.port_service(99999), "unknown")


class SubdomainGuardTests(unittest.TestCase):
    def test_enum_rejects_empty(self):
        result = asyncio.run(dns_tools.subdomain_enum(""))
        self.assertFalse(result["ok"])

    def test_enum_wordlist_permutations_offline(self):
        # wildcard detection will fail offline (no resolver); tool must still
        # return a structured result rather than raising
        base = dns_tools._load_wordlist("api,admin")
        expected = len(dns_tools._expand_permutations(base))
        self.assertGreater(expected, len(base), "permutations must expand the list")
        result = asyncio.run(dns_tools.subdomain_enum("example.invalid", wordlist="api,admin", permutations=True))
        self.assertIn("ok", result)
        self.assertEqual(result["wordlist_size"], expected)


if __name__ == "__main__":
    unittest.main()
