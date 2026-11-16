"""Offline tests for utilities: JWT, hashing, doctor."""

import asyncio
import base64
import json
import os
import tempfile
import unittest

from osint_mcp import util_tools


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class JwtTests(unittest.TestCase):
    def _token(self, header: dict, payload: dict) -> str:
        return ".".join([
            _b64url(json.dumps(header).encode()),
            _b64url(json.dumps(payload).encode()),
            "sig",
        ])

    def test_decode_valid_token(self):
        token = self._token({"alg": "HS256"}, {"sub": "u1", "exp": 9999999999})
        result = asyncio.run(util_tools.jwt_decode(token))
        self.assertTrue(result["ok"])
        self.assertEqual(result["payload"]["sub"], "u1")
        self.assertFalse(result["expired"])
        self.assertTrue(result["signature_present"])
        self.assertEqual(result["warnings"], [])

    def test_alg_none_flagged(self):
        token = self._token({"alg": "none"}, {"sub": "u1"})
        result = asyncio.run(util_tools.jwt_decode(token))
        self.assertTrue(result["ok"])
        self.assertIn("alg=none - unsigned token", result["warnings"])

    def test_expired_flagged(self):
        token = self._token({"alg": "HS256"}, {"exp": 1000})
        result = asyncio.run(util_tools.jwt_decode(token))
        self.assertTrue(result["expired"])
        self.assertIn("expired token", result["warnings"])

    def test_bearer_prefix_stripped(self):
        token = self._token({"alg": "HS256"}, {"sub": "u"})
        result = asyncio.run(util_tools.jwt_decode(f"Bearer {token}"))
        self.assertTrue(result["ok"])

    def test_garbage_rejected(self):
        result = asyncio.run(util_tools.jwt_decode("not.a.jwt!!!"))
        self.assertFalse(result["ok"])


class HashTests(unittest.TestCase):
    def test_hash_text(self):
        result = asyncio.run(util_tools.hash_text("abc"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["hashes"]["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_unknown_algorithm(self):
        result = asyncio.run(util_tools.hash_text("abc", algorithms="notahash"))
        self.assertFalse(result["ok"])
        self.assertIn("notahash", result["error"])


class DoctorTests(unittest.TestCase):
    def test_doctor_runs_and_reports(self):
        result = asyncio.run(util_tools.doctor())
        self.assertTrue(result["ok"], msg=str([c for c in result["checks"] if c["state"] == "fail"]))
        names = {c["name"] for c in result["checks"]}
        self.assertIn("python", names)
        self.assertIn("case database", names)
        self.assertIn("ssrf guard", names)
        self.assertIn("cache", names)

    def test_doctor_cli_subprocess(self):
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "osint_mcp", "doctor"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr[-500:])
        payload = json.loads(proc.stdout)
        self.assertIn("checks", payload)


class ImageExifTests(unittest.TestCase):
    def test_missing_file(self):
        result = asyncio.run(util_tools.image_exif("/nonexistent/definitely/missing.png"))
        self.assertFalse(result["ok"])

    def test_real_image_exif(self):
        from PIL import Image

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "t.png")
            Image.new("RGB", (4, 4), "red").save(path)
            result = asyncio.run(util_tools.image_exif(path))
            self.assertTrue(result["ok"])
            self.assertEqual(result["format"], "PNG")


if __name__ == "__main__":
    unittest.main()
