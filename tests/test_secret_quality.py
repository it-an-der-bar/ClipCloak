"""Secret detection measured against a corpus instead of single cases (tests/secret_corpus.py).

- every credential of the corpus (≈ 65 formats × 33 wrappers – text, code, config, markup, URL,
  split over string literals in Python/JS/Java/VB/PHP, base64 –, admin commands and config files,
  JWTs split at the dots, passwords copied alone) must be gone after redaction – and be found as a
  secret, not as something else;
- nothing in the negative corpus (code, logs, manifests, hashes, ids, paths, prose, and technical
  values in the same wrappers) may be reported as a secret;
- on the Python standard library (code and docs, several MB) at most a handful of findings per MB.

A miss prints the name of the case, so a new format or a regression is visible at once.
"""

import os
import sysconfig
import tempfile
import time
import unittest

from tests import helpers  # noqa: F401  (isolated config/data dirs)
from tests.secret_corpus import negatives, positives

from clipcloak.config import Config, engine_settings
from clipcloak.core.detectors import DetectorContext, builtin_detectors
from clipcloak.core.engine import Engine

SECRET_TYPES = {"SECRET", "PRIVATE_KEY", "CERTIFICATE"}


def engine() -> Engine:
    cfg = Config(os.path.join(tempfile.mkdtemp(), "config.yaml"))     # shipped defaults
    return Engine(engine_settings(cfg))


class SecretCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = engine()

    def test_all_credentials_are_found(self):
        misses = []
        cases = positives()
        for name, text, core in cases:
            out = self.e.process(text, "redact").output
            left = [core[i:i + 8] for i in range(max(1, len(core) - 7)) if core[i:i + 8] in out]
            wrong = [f"{f.type}:{f.text[:20]}" for f in self.e.analyze(text)
                     if f.type not in SECRET_TYPES and f.text in core and len(f.text) >= 6]
            if left or wrong:
                misses.append(f"{name}: {'left ' + left[0] if left else ''} {' '.join(wrong)}".strip())
        self.assertGreater(len(cases), 2000)
        self.assertEqual(misses, [], f"{len(misses)} of {len(cases)} missed")

    def test_nothing_else_is_a_secret(self):
        bad = []
        for name, text in negatives():
            for f in self.e.analyze(text):
                if f.type in ("SECRET", "PRIVATE_KEY"):
                    bad.append(f"{name}: {f.detector} {f.text[:40]!r}")
        self.assertEqual(bad, [])

    def test_base64_pem_is_typed(self):
        cert = dict(negatives())["cert-b64"]
        types = {f.type for f in self.e.analyze(cert)}
        self.assertIn("CERTIFICATE", types)
        key = next(t for n, t, _c in positives() if n == "ctx-kubeconfig-client-key")
        self.assertIn("PRIVATE_KEY", {f.type for f in self.e.analyze(key)})

    def test_surrogates_keep_the_format(self):
        cases = {n: (t, c) for n, t, c in positives()}
        heads = {"random-b64url-prefix-0/alone": "vbk_", "ctx-shadow": "root:$6$", "github-p/alone": "gh" + "p_",
                 "ctx-cisco-type7": "username admin privilege 15 password 7 ", "wireguard-key/alone": ""}
        for name, head in heads.items():
            text, core = cases[name]
            res = self.e.process(text, "pseudonymize")
            out = res.output
            self.assertEqual(len(out), len(text), name)
            self.assertNotIn(core[:12], out, name)
            self.assertEqual(self.e.revert(out).output, text, name)
            self.assertTrue(out.startswith(head), (name, out[:20]))      # prefix / algorithm stays
            if name == "ctx-cisco-type7":
                self.assertRegex(out.rsplit(" ", 1)[1], r"^[0-9A-F]+$")  # upper-case hex stays upper case


class StdlibPrecisionTest(unittest.TestCase):
    """Real code and documentation: the Python standard library of this interpreter."""

    MB = 4.0

    def test_few_findings_in_real_code(self):
        root = sysconfig.get_paths().get("stdlib")
        if not root or not os.path.isdir(root):
            self.skipTest("no standard library sources")
        files = []
        for dp, dn, fn in os.walk(root):
            dn[:] = sorted(d for d in dn if d not in ("test", "tests", "idlelib", "site-packages", "dist-packages",
                                                      "__pycache__", "lib2to3", "ensurepip"))
            files += [os.path.join(dp, f) for f in sorted(fn) if f.endswith((".py", ".txt", ".rst"))]
        if not files:
            self.skipTest("no standard library sources")
        dets = [d for d in builtin_detectors() if d.default_enabled and set(d.types) & SECRET_TYPES]
        ctx = DetectorContext()
        size, hits, t0 = 0, [], time.perf_counter()
        for i, path in enumerate(files):
            if i % 3 or size > self.MB * 1e6:
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            size += len(text)
            for d in dets:
                hits += [(os.path.basename(path), f.text[:30]) for f in d.find(text, ctx)
                         if f.type in ("SECRET", "PRIVATE_KEY")]
        per_mb = len(hits) / (size / 1e6)
        print(f"\nstdlib {size / 1e6:.1f} MB: {len(hits)} secret findings ({per_mb:.1f}/MB) "
              f"in {time.perf_counter() - t0:.1f} s")
        self.assertLess(per_mb, 3.0, hits[:20])


if __name__ == "__main__":
    unittest.main()
