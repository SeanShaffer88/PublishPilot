import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import publishpilot as pp


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, data: bytes):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p


class TestCheck(TempDirCase):
    def test_size_limit_refusal(self):
        # JSON encoding adds quotes/escapes; a file well over the limit
        # must be refused with split advice.
        p = self.write("big.py", ("x" * 120_000).encode())
        result = pp.check_file(p, "big.py")
        self.assertEqual(result["status"], "REFUSAL")
        msgs = " ".join(f.message for f in result["findings"])
        self.assertIn("split", msgs.lower())
        self.assertIn("105000", msgs)

    def test_size_under_limit_ok(self):
        p = self.write("small.py", b"print('hi')\n")
        result = pp.check_file(p, "small.py")
        self.assertEqual(result["status"], "OK")

    def test_binary_refusal_nul(self):
        p = self.write("blob.py", b"\x00\x01\x02binary")
        result = pp.check_file(p, "blob.py")
        self.assertEqual(result["status"], "REFUSAL")

    def test_binary_refusal_not_utf8(self):
        p = self.write("bad.py", b"\xff\xfe\xfa invalid utf8")
        result = pp.check_file(p, "bad.py")
        self.assertEqual(result["status"], "REFUSAL")

    def test_workflows_refusal(self):
        p = self.write(".github/workflows/ci.yml", b"name: ci\n")
        result = pp.check_file(p, ".github/workflows/ci.yml")
        self.assertEqual(result["status"], "REFUSAL")
        msgs = " ".join(f.message for f in result["findings"])
        self.assertIn("workflows", msgs.lower())

    def test_non_workflows_github_path_ok(self):
        p = self.write(".github/ISSUE_TEMPLATE.md", b"# hi\n")
        result = pp.check_file(p, ".github/ISSUE_TEMPLATE.md")
        self.assertNotEqual(result["status"], "REFUSAL")

    def test_base64_detection_positive(self):
        payload = ("The quick brown fox jumps over the lazy dog. " * 4).encode()
        blob = base64.b64encode(payload)
        p = self.write("suspicious.py", blob + b"\n")
        result = pp.check_file(p, "suspicious.py")
        self.assertEqual(result["status"], "WARNING")
        msgs = " ".join(f.message for f in result["findings"])
        self.assertIn("base64", msgs.lower())

    def test_base64_detection_negative_normal_code(self):
        code = (
            "import base64\n\n\n"
            "def encode(data: bytes) -> str:\n"
            "    return base64.b64encode(data).decode('ascii')\n\n"
            "print(encode(b'hello'))  # normal code, spaces & punctuation\n"
        )
        p = self.write("normal.py", code.encode())
        result = pp.check_file(p, "normal.py")
        self.assertEqual(result["status"], "OK")
        self.assertFalse(pp.looks_like_base64_blob(code))

    def test_base64_detection_negative_wrong_extension(self):
        # Same blob in a .bin-named file (not a known text extension)
        # must not produce the base64 warning path from extension gating;
        # the detector itself fires, but check only warns for text exts.
        payload = ("hello world, this is a test payload. " * 4).encode()
        blob = base64.b64encode(payload)
        p = self.write("data.bin", blob)
        result = pp.check_file(p, "data.bin")
        msgs = " ".join(f.message for f in result["findings"])
        self.assertNotIn("base64 blob", msgs.lower())

    def test_crlf_detection(self):
        p = self.write("win.txt", b"line one\r\nline two\r\n")
        result = pp.check_file(p, "win.txt")
        self.assertEqual(result["endings"], "CRLF")
        self.assertEqual(pp.classify_line_endings(b"a\r\nb\r\n"), "CRLF")

    def test_lf_detection(self):
        self.assertEqual(pp.classify_line_endings(b"a\nb\n"), "LF")

    def test_mixed_detection(self):
        self.assertEqual(pp.classify_line_endings(b"a\r\nb\n"), "mixed")

    def test_empty_file_warning(self):
        p = self.write("empty.py", b"")
        result = pp.check_file(p, "empty.py")
        self.assertEqual(result["status"], "WARNING")

    def test_executable_warning(self):
        import os
        import stat
        p = self.write("run.sh", b"#!/bin/sh\necho hi\n")
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
        result = pp.check_file(p, "run.sh")
        self.assertEqual(result["status"], "WARNING")
        msgs = " ".join(f.message for f in result["findings"])
        self.assertIn("sh ./", msgs)


class TestBlobSha(unittest.TestCase):
    def test_blob_sha_known_vector(self):
        data = b"hello\n"
        # Independent computation in the test, per the git formula.
        header = b"blob " + str(len(data)).encode() + b"\0"
        expected = hashlib.sha1(header + data).hexdigest()
        self.assertEqual(pp.git_blob_sha1(data), expected)
        # Also the well-known git blob hash for "hello\n".
        self.assertEqual(expected, "ce013625030ba8dba906f756967f9e9ca394464a")

    def test_blob_sha_empty(self):
        expected = hashlib.sha1(b"blob 0\0").hexdigest()
        self.assertEqual(pp.git_blob_sha1(b""), expected)


class TestManifest(TempDirCase):
    def test_manifest_generation(self):
        self.write("a.txt", b"hello\n")
        self.write("sub/b.py", b"print('x')\r\n")
        manifest = pp.build_manifest(self.root, pp.walk_files(self.root))
        self.assertEqual(manifest["tool"], "publishpilot")
        by_path = {e["path"]: e for e in manifest["files"]}
        self.assertIn("a.txt", by_path)
        self.assertIn("sub/b.py", by_path)
        a = by_path["a.txt"]
        self.assertEqual(a["size"], 6)
        self.assertEqual(a["sha256"], hashlib.sha256(b"hello\n").hexdigest())
        self.assertEqual(a["blob_sha1"], pp.git_blob_sha1(b"hello\n"))
        self.assertEqual(a["line_endings"], "LF")
        self.assertFalse(a["executable"])
        self.assertEqual(by_path["sub/b.py"]["line_endings"], "CRLF")
        # Manifest must be JSON-serializable.
        json.dumps(manifest)


class TestVerify(TempDirCase):
    def test_verify_match_and_mismatch_and_deferred(self):
        entry = {"path": "a.txt", "sha256": hashlib.sha256(b"hello\n").hexdigest()}

        def good_fetcher(url):
            return b"hello\n"

        def bad_fetcher(url):
            return b"different\n"

        def broken_fetcher(url):
            raise OSError("network down")

        self.assertEqual(
            pp.verify_entry(entry, "o", "r", "main", fetcher=good_fetcher), "match")
        self.assertEqual(
            pp.verify_entry(entry, "o", "r", "main", fetcher=bad_fetcher), "mismatch")
        # Network failures are deferred, never a crash.
        self.assertEqual(
            pp.verify_entry(entry, "o", "r", "main", fetcher=broken_fetcher), "deferred")


class TestJsonSize(unittest.TestCase):
    def test_json_encoded_size_counts_escapes(self):
        # A quote character expands in JSON encoding.
        self.assertGreater(pp.json_encoded_size('"'), len('"'))
        self.assertEqual(pp.json_encoded_size("abc"), len(json.dumps("abc").encode()))


if __name__ == "__main__":
    unittest.main()
