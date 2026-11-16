"""Tests for the v2 reliability core in osint_mcp.common (offline)."""

import asyncio
import os
import unittest
from typing import ClassVar
from unittest.mock import patch

import httpx

from osint_mcp import common


class CacheTests(unittest.TestCase):
    def test_cache_respects_ttl(self):
        common._CACHE.clear()
        common.cache_set("ttl_key", "v")
        self.assertEqual(common.cache_get("ttl_key", ttl=10), "v")
        self.assertIsNone(common.cache_get("ttl_key", ttl=-1))

    def test_cache_is_bounded(self):
        common._CACHE.clear()
        for i in range(common.CACHE_MAX_ENTRIES + 100):
            common.cache_set(f"k{i}", i)
        self.assertLessEqual(len(common._CACHE), common.CACHE_MAX_ENTRIES)
        # oldest entries evicted
        self.assertIsNone(common.cache_get("k0"))
        self.assertEqual(common.cache_get(f"k{common.CACHE_MAX_ENTRIES + 99}"), common.CACHE_MAX_ENTRIES + 99)


class HelpersTests(unittest.TestCase):
    def test_normalize_target(self):
        cases = {
            "https://example.com/path?q=1": "example.com",
            "http://user:pass@example.com:8080/x": "example.com",
            "example.com.": "example.com",
            "[2001:db8::1]:443": "2001:db8::1",
            " https://EXAMPLE.com ": "EXAMPLE.com",
        }
        for value, expected in cases.items():
            self.assertEqual(common.normalize_target(value), expected)

    def test_ensure_url_and_url_host(self):
        self.assertEqual(common.ensure_url("example.com"), "https://example.com")
        self.assertEqual(common.url_host("https://example.com/a?b=c"), "example.com")
        self.assertEqual(common.url_host("not a url"), "")

    def test_error_result_is_structured(self):
        result = common.error_result(httpx.ConnectError("boom"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "ConnectError")
        self.assertTrue(result["retryable"])
        self.assertIn("boom", result["error"])

    def test_fail_helper(self):
        result = common.fail("bad input", code="invalid", retryable=False)
        self.assertEqual(result["error_code"], "invalid")
        self.assertFalse(result["retryable"])

    def test_api_key_blank_env_falls_through(self):
        with patch.dict(os.environ, {"TESTBLANK_API_KEY": "   "}):
            self.assertIsNone(common.api_key("testblank"))


class SSRFGuardTests(unittest.TestCase):
    blocked: ClassVar[list[str]] = [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.10/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "file:///etc/passwd",
    ]

    def test_private_targets_blocked(self):
        async def run():
            for url in self.blocked:
                with self.assertRaises(common.PrivateAddressError, msg=url):
                    await common.assert_public_url(url)

        asyncio.run(run())

    def test_public_hostname_allowed(self):
        async def run():
            await common.assert_public_url("https://github.com")

        asyncio.run(run())

    def test_allow_private_flag(self):
        with patch.dict(os.environ, {"OSINT_ALLOW_PRIVATE": "1"}):
            self.assertTrue(common.allow_private())

            async def run():
                await common.assert_public_url("http://127.0.0.1/")  # allowed by flag

            asyncio.run(run())


class RequestRetryTests(unittest.TestCase):
    def _transport(self, responses):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            index = min(calls["n"], len(responses) - 1)
            calls["n"] += 1
            return responses[index]

        return httpx.MockTransport(handler), calls

    def test_retries_on_503_then_succeeds(self):
        transport, calls = self._transport([
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ])
        async def run():
            with patch.object(common, "get_client", return_value=httpx.AsyncClient(transport=transport)):
                with patch.object(common, "assert_public_url", return_value=None):
                    with patch.object(common.asyncio, "sleep", return_value=None):
                        return await common.request("https://example.com/api")

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls["n"], 2)

    def test_no_retry_for_post(self):
        transport, calls = self._transport([httpx.Response(503)])
        async def run():
            with patch.object(common, "get_client", return_value=httpx.AsyncClient(transport=transport)):
                with patch.object(common, "assert_public_url", return_value=None):
                    return await common.request("https://example.com/api", method="POST")

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(calls["n"], 1)

    def test_retry_after_honoured(self):
        transport, calls = self._transport([
            httpx.Response(429, headers={"Retry-After": "1"}),
            httpx.Response(200),
        ])
        async def run():
            with patch.object(common, "get_client", return_value=httpx.AsyncClient(transport=transport)):
                with patch.object(common, "assert_public_url", return_value=None):
                    return await common.request("https://example.com/")

        asyncio.run(run())
        self.assertEqual(calls["n"], 2)


class RedirectTests(unittest.TestCase):
    def test_redirects_are_followed_with_history(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(302, headers={"Location": "/final"})
            return httpx.Response(200, json={"arrived": True})

        transport = httpx.MockTransport(handler)
        async def run():
            with patch.object(common, "get_client", return_value=httpx.AsyncClient(transport=transport)):
                with patch.object(common, "assert_public_url", return_value=None):
                    return await common.request("https://example.com/start")

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.history), 1)
        self.assertEqual(response.json(), {"arrived": True})

    def test_redirect_to_private_is_blocked(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8500/v1/health"})

        transport = httpx.MockTransport(handler)
        real_guard = common.assert_public_url

        async def selective(url: str) -> None:
            if url.startswith("https://example.com"):
                return  # first hop: public target allowed
            await real_guard(url)  # every following hop: real guard applies

        async def run():
            with patch.object(common, "get_client", return_value=httpx.AsyncClient(transport=transport)):
                with patch.object(common, "assert_public_url", selective):
                    return await common.request("https://example.com/open-redirect")

        with self.assertRaises(common.PrivateAddressError):
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
