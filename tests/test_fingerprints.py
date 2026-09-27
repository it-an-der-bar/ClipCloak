"""Optional detector for public key/certificate identifiers."""

import re
import unittest

from tests import helpers  # noqa: F401

from clipcloak.config import Config, engine_settings
from clipcloak.core.engine import Engine
from clipcloak.core.entities import CATEGORY_OF
from clipcloak.core.vault import Vault


def engine(enabled=True):
    s = engine_settings(Config())
    if enabled:
        s.enabled_detectors.add("fingerprints")
    else:
        s.enabled_detectors.discard("fingerprints")
    return Engine(s, Vault("t"))


def prints(e, text):
    return [f.text for f in e.analyze(text) if f.type == "FINGERPRINT"]


class FingerprintTest(unittest.TestCase):
    OWN = "Acme.Licensing, Version=2.1.0.0, Culture=neutral, PublicKeyToken=3f1a9c0e5b7d2468"
    MS = "System.Private.CoreLib, Version=10.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e"

    def test_off_by_default(self):
        self.assertEqual(prints(engine(False), self.OWN), [])
        self.assertEqual(CATEGORY_OF["FINGERPRINT"], "ids")

    def test_public_key_token(self):
        e = engine()
        self.assertEqual(prints(e, self.OWN), ["3f1a9c0e5b7d2468"])
        self.assertEqual(prints(e, self.MS), [])               # Microsoft/.NET: identifies nobody
        self.assertEqual(prints(e, "PublicKeyToken=null"), [])

    def test_thumbprints_serials_ssh_gpg(self):
        e = engine()
        cases = {
            "Thumbprint: 9A3F5C2D8E1B7046A2C4E6F8091B3D5F7A9C1E24": "9A3F5C2D8E1B7046A2C4E6F8091B3D5F7A9C1E24",
            "Serial Number: 4e:1a:9c:77:02:bd:3f:81:6a:05:c2:d9": "4e:1a:9c:77:02:bd:3f:81:6a:05:c2:d9",
            "ED25519 key fingerprint is SHA256:Qm4k7bT2xY9vN3pL8wR5sA1dF6gH0jK2zX4cV7bN9mQ.":
                "Qm4k7bT2xY9vN3pL8wR5sA1dF6gH0jK2zX4cV7bN9mQ",
            "pub   rsa4096 2023-01-05 [SC]\n      8C2F4A1E9D3B7065C8A2E4F6019B3D5E7A9C1F24\nuid   Max":
                "8C2F4A1E9D3B7065C8A2E4F6019B3D5E7A9C1F24",
            "7D2E9A4C1F6B3085D7A1C3E5F8092B4D6A8C0E13  CN=vpn.acme.local":
                "7D2E9A4C1F6B3085D7A1C3E5F8092B4D6A8C0E13",
            "Key fingerprint = 1A2B 3C4D 5E6F 7A8B 9C0D  1E2F 3A4B 5C6D 7E8F 9A0B":
                "1A2B 3C4D 5E6F 7A8B 9C0D  1E2F 3A4B 5C6D 7E8F 9A0B",
        }
        for text, want in cases.items():
            with self.subTest(text=text[:30]):
                self.assertIn(want, prints(e, text))

    def test_placeholders_ignored(self):
        e = engine()
        self.assertEqual(prints(e, "Thumbprint: 0000000000000000000000000000000000000000"), [])

    def test_format_preserving_consistent_and_reversible(self):
        e = engine()
        text = self.OWN + "\n" + self.MS + "\nagain: PublicKeyToken=3f1a9c0e5b7d2468\n" \
            "Serial Number: 4e:1a:9c:77:02:bd:3f:81:6a:05:c2:d9"
        out = e.process(text, "pseudonymize").output
        self.assertNotIn("3f1a9c0e5b7d2468", out)
        self.assertIn("7cec85d7bea7798e", out)
        new = re.findall(r"PublicKeyToken=([0-9a-f]{16})\b", out)
        self.assertEqual(len(new), 3)
        self.assertEqual(new[0], new[2])
        self.assertRegex(out, r"Serial Number: (?:[0-9a-f]{2}:){11}[0-9a-f]{2}")
        self.assertEqual(e.revert(out).output, text)


if __name__ == "__main__":
    unittest.main()
