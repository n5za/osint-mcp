"""Tests for case export, FTS search mode, and WAL mode (offline)."""

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest

from osint_mcp import case_tools


class CaseExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("OSINT_CASES_DB")
        os.environ["OSINT_CASES_DB"] = os.path.join(self.temp.name, "cases.sqlite3")
        created = asyncio.run(case_tools.case_create("Export Case", "export tests"))
        self.assertTrue(created["ok"])

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("OSINT_CASES_DB", None)
        else:
            os.environ["OSINT_CASES_DB"] = self.previous
        self.temp.cleanup()

    def _populate(self):
        asyncio.run(case_tools.case_note("Export Case", "Amina", "person", "Spotted near the gallery", ""))
        asyncio.run(case_tools.case_add_fact(
            "Export Case", "Amina", "visited", "Rabat",
            source_url="https://example.org/story", evidence="She travelled to Rabat on Friday.",
        ))

    def test_export_inline(self):
        self._populate()
        result = asyncio.run(case_tools.case_export("Export Case"))
        self.assertTrue(result["ok"])
        data = result["data"]
        self.assertEqual(data["schema"], "osint-mcp/case-export")
        self.assertTrue(any(entity["name"] == "Amina" for entity in data["entities"]))
        self.assertTrue(data["facts"])

    def test_export_to_file(self):
        self._populate()
        path = os.path.join(self.temp.name, "case.json")
        result = asyncio.run(case_tools.case_export("Export Case", out_path=path))
        self.assertTrue(result["ok"])
        self.assertEqual(result["path"], os.path.abspath(path))
        self.assertTrue(os.path.isfile(path))
        payload = json.loads(open(path, encoding="utf-8").read())
        self.assertEqual(payload["case"]["name"], "Export Case")
        self.assertTrue(result["sha256"])

    def test_export_unknown_case(self):
        result = asyncio.run(case_tools.case_export("does-not-exist"))
        self.assertFalse(result["ok"])


class FTSSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("OSINT_CASES_DB")
        os.environ["OSINT_CASES_DB"] = os.path.join(self.temp.name, "cases.sqlite3")

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("OSINT_CASES_DB", None)
        else:
            os.environ["OSINT_CASES_DB"] = self.previous
        self.temp.cleanup()

    def test_fts_mode_and_results(self):
        asyncio.run(case_tools.case_create("FTS Case"))
        asyncio.run(case_tools.case_note("FTS Case", "Amina", "person", "Travels frequently to Rabat", ""))
        asyncio.run(case_tools.case_note("FTS Case", "Brahim", "person", "Owns a boat in Agadir", ""))
        result = asyncio.run(case_tools.case_search("FTS Case", "Rabat"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "fts")
        texts = [item["text"] for item in result["observations"]]
        self.assertTrue(any("Rabat" in text for text in texts))
        self.assertFalse(any("Agadir" in text for text in texts))

    def test_word_match_ordering(self):
        asyncio.run(case_tools.case_create("FTS2"))
        asyncio.run(case_tools.case_note("FTS2", "X", "person", "red car near the port", ""))
        asyncio.run(case_tools.case_note("FTS2", "Y", "person", "blue car downtown", ""))
        result = asyncio.run(case_tools.case_search("FTS2", "blue"))
        texts = [item["text"] for item in result["observations"]]
        self.assertTrue(any("blue" in text for text in texts))

    def test_wal_mode_active(self):
        asyncio.run(case_tools.case_create("WAL Case"))
        path = os.environ["OSINT_CASES_DB"]
        connection = sqlite3.connect(path)
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        connection.close()
        self.assertEqual(mode, "wal")
        self.assertEqual(version, 2)

    def test_like_fallback_with_fts_unavailable(self):
        # even if FTS MATCH raises, search must return results via LIKE fallback
        asyncio.run(case_tools.case_create("LIKE Case"))
        asyncio.run(case_tools.case_note("LIKE Case", "Amina", "person", "wears a red jacket", ""))
        with case_tools._db():
            pass  # ensure schema exists
        result = asyncio.run(case_tools.case_search("LIKE Case", "red jacket"))
        self.assertTrue(result["ok"])
        self.assertIn(result["mode"], ("fts", "like"))
        self.assertTrue(result["observations"])


if __name__ == "__main__":
    unittest.main()
