"""Offline tests for search tools (parsing + fallback logic)."""

import unittest

from osint_mcp import search_tools

DDG_HTML = """
<html><body>
<div class="result">
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fone&amp;rut=x">First Result</a>
  <a class="result__snippet">Snippet one</a>
</div>
<div class="result">
  <a class="result__a" href="https://example.com/two">Second Result</a>
  <span class="result__snippet">Snippet two</span>
</div>
<article class="result">
  <h2><a href="https://example.org/three">Third</a></h2>
</article>
</body></html>
"""

DDG_LITE = """
<html><body>
<table><tr><td>
<a class="result-link" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Flite.example%2Fa">Lite A</a>
</td></tr></table>
</body></html>
"""


class ParseTests(unittest.TestCase):
    def test_parse_ddg_html(self):
        results = search_tools._parse_ddg_html(DDG_HTML)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["url"], "https://example.org/one")
        self.assertEqual(results[0]["title"], "First Result")
        self.assertEqual(results[0]["snippet"], "Snippet one")
        self.assertEqual(results[1]["url"], "https://example.com/two")

    def test_parse_ddg_lite(self):
        results = search_tools._parse_ddg_lite(DDG_LITE)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://lite.example/a")

    def test_blocked_page_detector(self):
        self.assertTrue(search_tools._blocked_page("Sorry, an anomaly was detected"))
        self.assertFalse(search_tools._blocked_page("<html>normal</html>"))


class DorksTests(unittest.TestCase):
    def test_dork_categories_render_domain(self):
        import asyncio

        result = asyncio.run(search_tools.google_dorks("example.com", category="git_exposure"))
        self.assertTrue(result["ok"])
        git_dorks = [item for item in result["dorks"] if item["category"] == "git_exposure"]
        self.assertTrue(git_dorks)
        self.assertTrue(all("example.com" in item["dork"] for item in git_dorks))

    def test_unknown_category_rejected(self):
        import asyncio

        result = asyncio.run(search_tools.google_dorks("example.com", category="nope"))
        self.assertFalse(result["ok"])
        self.assertIn("all", result["available"])


if __name__ == "__main__":
    unittest.main()
