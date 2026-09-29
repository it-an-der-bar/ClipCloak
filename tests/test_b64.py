"""Base64 recognition, decoding and encoding."""

import base64
import unittest

from tests import helpers  # noqa: F401

from clipcloak.core import b64


class Base64Test(unittest.TestCase):
    def test_roundtrip(self):
        for s in ("hello world", "user: admin\npassword: Geheim!2024\n", "Grüße aus München ✓", "a"):
            self.assertEqual(b64.decode(b64.encode(s)), s)
            self.assertEqual(b64.decode(b64.encode(s, urlsafe=True)), s)

    def test_variants(self):
        self.assertEqual(b64.decode("aGVsbG8gd29ybGQ="), "hello world")
        self.assertEqual(b64.decode("aGVsbG8gd29ybGQ"), "hello world")                # no padding
        self.assertEqual(b64.decode("  aGVsbG8g\n d29ybGQ=\n"), "hello world")        # wrapped
        self.assertEqual(b64.decode("eyJhbGciOiJIUzI1NiJ9"), '{"alg":"HS256"}')
        self.assertEqual(b64.decode("Pz8-Pz8-Pz8-IG9rPw=="), "??>??>??> ok?")         # URL-safe

    def test_short_values_only_on_request(self):
        # Kubernetes secrets: short values – the explicit action decodes them
        self.assertEqual(b64.decode("YWRtaW4="), "admin")
        self.assertEqual(b64.decode("dGVzdA"), "test")
        self.assertIsNone(b64.decode("dGVzdA", strict=True))          # watcher: too short, no padding
        self.assertEqual(b64.decode("YWRtaW4=", strict=True), "admin")  # padding makes it clear

    def test_not_base64(self):
        for s in ("Hallo Welt", "HelloWorld12", "Kubernetes123", "/usr/local/bin/python3", "abcdEFGH1234",
                  "ContainerRegistry", "deadbeefcafebabe00112233", "0123456789ab", "abcd", "",
                  "Mail an max.muster@firma.de", base64.b64encode(bytes(range(48))).decode()):
            self.assertIsNone(b64.decode(s, strict=True), s)
        self.assertIsNone(b64.decode(base64.b64encode(bytes(range(48))).decode()))   # binary
        self.assertIsNone(b64.decode("aGVsbG8=d29y"))                                   # padding inside


if __name__ == "__main__":
    unittest.main()
