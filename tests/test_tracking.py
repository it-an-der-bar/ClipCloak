"""Tracking parameters, redirect wrappers and text fragments are removed from links."""

import unittest

from clipcloak.config import Config, engine_settings
from clipcloak.core.detectors.tracking import unwrap
from clipcloak.core.engine import Engine
from clipcloak.core.formats import process_html
from clipcloak.core.vault import Vault


def engine(**lists):
    cfg = Config()
    cfg.set("lists.allow_domains", ["example.com", "example.org", "youtu.be", "heise.de", "amazon.de",
                                    "contoso.com", "mozilla.org", "x.com"])
    for k, v in lists.items():
        cfg.set("lists." + k, v)
    return Engine(engine_settings(cfg), Vault("t"))


CASES = [
    ("https://www.heise.de/news/a.html?utm_source=newsletter&utm_medium=email&wt_mc=x",
     "https://www.heise.de/news/a.html"),
    ("https://example.com/p?id=5&utm_campaign=h&color=red&fbclid=IwAR0abc", "https://example.com/p?id=5&color=red"),
    ("https://example.com/p?utm_campaign=h&gclid=1&id=5", "https://example.com/p?id=5"),
    ("https://example.com/p?id=5&mc_eid=12345", "https://example.com/p?id=5"),
    ("Video: https://youtu.be/abc?si=AbCdEf123&t=42.", "Video: https://youtu.be/abc?t=42."),
    ("https://www.amazon.de/P/dp/B0AB/ref=sr_1_3?crid=2X&keywords=kabel&qid=17&sr=8-3",
     "https://www.amazon.de/P/dp/B0AB?keywords=kabel"),
    ("https://developer.mozilla.org/docs/Web#:~:text=hello", "https://developer.mozilla.org/docs/Web"),
    ("https://example.com/a?page=2#section:~:text=foo", "https://example.com/a?page=2#section"),
    ("https://x.com/u/status/1?s=20&t=abc", "https://x.com/u/status/1"),
    ("(see https://example.com/?utm_source=a)", "(see https://example.com/)"),
    ("https://example.com/search?q=test&page=2 stays", "https://example.com/search?q=test&page=2 stays"),
    ("https://example.com/watch?t=42&si=1", "https://example.com/watch?t=42&si=1"),   # si only on YouTube/Spotify
]


class TrackingTest(unittest.TestCase):
    def test_parameters_removed_in_every_mode(self):
        for mode in ("pseudonymize", "anonymize", "redact"):
            e = engine()
            for src, want in CASES:
                with self.subTest(mode=mode, src=src):
                    self.assertEqual(e.process(src, mode).output, want)

    def test_safe_links_unwrapped_and_target_processed(self):
        url = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.contoso.com"
               "%2Flogin%3Futm_source%3Dmail&data=05%7C01%7Cjonas.hartmann%40contoso.com%7Cabc&sdata=xyz&reserved=0")
        e = engine()
        res = e.process("Link: " + url + " bitte", "pseudonymize")
        self.assertEqual(res.output, "Link: https://portal.contoso.com/login bitte")
        self.assertNotIn("hartmann", res.output)
        # the target's domain is pseudonymised like any other when not allowed
        e2 = Engine(engine_settings(Config()), Vault("t2"))
        out = e2.process(url, "pseudonymize").output
        self.assertTrue(out.startswith("https://portal.") and out.endswith("/login"))
        self.assertNotIn("contoso", out)

    def test_unwrap(self):
        self.assertEqual(unwrap("https://www.google.com/url?sa=t&q=&url=https%3A%2F%2Fexample.org%2Fdoc&ved=2"),
                         "https://example.org/doc")
        self.assertEqual(unwrap("https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2F&h=AT0"),
                         "https://example.org/")
        self.assertEqual(unwrap("https://urldefense.proofpoint.com/v2/url?u=https-3A__example.org_a&d=x"),
                         "https://example.org/a")
        self.assertEqual(unwrap("https://urldefense.com/v3/__https://example.org/a__;!!abc$"), "https://example.org/a")
        self.assertIsNone(unwrap("https://example.org/url?q=https://x.org"))

    def test_extra_parameters(self):
        e = engine(tracking_params=["campaign_id"])
        self.assertEqual(e.process("https://example.com/?campaign_id=7&a=1", "pseudonymize").output,
                         "https://example.com/?a=1")

    def test_html_links(self):
        e = engine()
        html = '<p>Hier <a href="https://example.com/p?id=5&amp;utm_source=x">Link</a></p>'
        out = process_html(html, lambda s: e.process(s, "pseudonymize"))
        self.assertIn('href="https://example.com/p?id=5"', out)

    def test_findings_visible(self):
        found = engine().analyze("https://example.com/p?id=5&utm_source=x")
        self.assertIn(("TRACKING", "&utm_source=x"), [(f.type, f.text) for f in found])


if __name__ == "__main__":
    unittest.main()
