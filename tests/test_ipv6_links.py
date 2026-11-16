"""Regression coverage for pages hosted on IPv6 literals."""

import unittest
from unittest.mock import AsyncMock, patch

import httpx

from osint_mcp import web_tools


class IPv6LinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_extract_links_keeps_same_ipv6_host_internal(self):
        url = "https://[2001:db8::1]:8443/index"
        response = httpx.Response(
            200,
            text='<a href="/about">About</a><a href="https://example.org/">External</a>',
            request=httpx.Request("GET", url),
        )
        with patch.object(web_tools, "request", new=AsyncMock(return_value=response)):
            result = await web_tools.extract_links(url)

        self.assertTrue(result["ok"])
        self.assertEqual(result["internal"], ["https://[2001:db8::1]:8443/about"])
        self.assertEqual(result["external"], ["https://example.org/"])


if __name__ == "__main__":
    unittest.main()
