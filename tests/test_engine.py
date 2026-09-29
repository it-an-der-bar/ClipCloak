import ipaddress
import json
import re
import unittest

import yaml

from tests.helpers import GLPAT, PEM_HEAD, PEM_TAIL, SAMPLE
from clipcloak.core.detectors import DetectorContext
from clipcloak.core.engine import Engine, EngineSettings
from clipcloak.core.formats import process_html, strip_cf_html
from clipcloak.core.surrogates import SurrogateSettings
from clipcloak.core.vault import Vault


class PseudonymiseRevert(unittest.TestCase):
    def setUp(self):
        self.e = Engine()

    def test_roundtrip_sample(self):
        r = self.e.process(SAMPLE, "pseudonymize")
        self.assertTrue(r.changed)
        for secret in ("contoso", "10.88.10.10", "hartmann", "Geheim", "S3cr3t", "hunter22", "dbpass99",
                       GLPAT, "DE89 3704", "4111 1111", "mhartmann",
                       "1004336348", "/home/jhartmann/"):
            self.assertNotIn(secret.lower(), r.output.lower(), secret)
        self.assertEqual(self.e.revert(r.output).output, SAMPLE)

    def test_consistency_between_calls(self):
        a = self.e.process("Host srv01.contoso.de 10.1.2.3 j.hartmann@contoso.de", "pseudonymize").output
        b = self.e.process("Wieder 10.1.2.3 und srv01.contoso.de", "pseudonymize").output
        ip_a = re.search(r"10\.\d+\.\d+\.\d+", a).group(0)
        self.assertIn(ip_a, b)
        dom = re.search(r"srv01\.[a-z]+\.de", a).group(0)
        self.assertIn(dom, b)
        mail_dom = a.split("@")[1]
        self.assertEqual(mail_dom, dom.split(".", 1)[1])   # same registrable domain

    def test_logical_ips(self):
        out = self.e.process("gw 10.88.10.1 host 10.88.10.10 net 10.88.10.0/24 pub 85.10.20.30", "pseudonymize").output
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+(?:/\d+)?", out)
        gw, host, net, pub = ips
        self.assertTrue(gw.endswith(".1"))
        n = ipaddress.ip_network(net)
        self.assertEqual(n.prefixlen, 24)
        self.assertIn(ipaddress.ip_address(gw), n)
        self.assertIn(ipaddress.ip_address(host), n)
        self.assertTrue(ipaddress.ip_address(host).is_private)
        self.assertTrue(ipaddress.ip_address(pub).is_global)

    def test_revert_llm_invented_ip_in_known_subnet(self):
        out = self.e.process("Server 10.88.10.10", "pseudonymize").output
        sur = ipaddress.ip_address(out.split()[-1])
        invented = str(ipaddress.ip_address(int(sur) & ~0xFF | 77))
        back = self.e.revert(f"Setze {invented} als DNS und 8.8.8.8 als Fallback").output
        orig = re.search(r"10\.88\.10\.\d+", back).group(0)       # same original subnet
        self.assertEqual(self.e.process(orig, "pseudonymize").output, invented)
        self.assertIn("8.8.8.8", back)

    def test_revert_case_insensitive_domain_and_name_tokens(self):
        out = self.e.process("jonas.hartmann@contoso.com", "pseudonymize").output
        local, dom = out.split("@")
        first, last = local.split(".")
        llm = f"Hallo {first.title()} {last.title()}, siehe {dom.upper()}."
        self.assertEqual(self.e.revert(llm).output, "Hallo Jonas Hartmann, siehe contoso.com.")

    def test_learned_names(self):
        out = self.e.process("Jonas Hartmann <jonas.hartmann@contoso.com>", "pseudonymize").output
        self.assertNotIn("Jonas", out)
        self.assertNotIn("Hartmann", out)
        first = out.split()[0]
        self.assertIn(first.lower() + ".", out)

    def test_skip_known_surrogates(self):
        out1 = self.e.process("10.1.2.3 und kunde.contoso.de", "pseudonymize").output
        out2 = self.e.process(out1, "pseudonymize").output
        # domains/names already pseudonymised stay; IPs are always processed (surrogates share
        # the private ranges with real addresses, skipping them would leak real ones)
        self.assertEqual(out1.split()[1:], out2.split()[1:])
        self.assertNotEqual(out1.split()[0], out2.split()[0])
        self.assertEqual(self.e.revert(self.e.revert(out2).output).output, "10.1.2.3 und kunde.contoso.de")

    def test_anonymize_realistic_not_revertible(self):
        r = self.e.process("10.1.2.3 j.hartmann@contoso.de", "anonymize")
        self.assertTrue(r.changed)
        self.assertEqual(self.e.revert(r.output).output, r.output)
        self.assertEqual(len(self.e.vault.entries), 0)

    def test_anonymize_placeholder(self):
        s = EngineSettings(anonymize_style="placeholder")
        e = Engine(s)
        out = e.process("10.1.2.3 10.1.2.4 10.1.2.3", "anonymize").output
        self.assertEqual(out, "<IPV4_1> <IPV4_2> <IPV4_1>")
        self.assertEqual(e.anon_vault.entries, {})
        self.assertFalse(any("10.1.2" in k for k in e.anon_vault.anon_map))

    def test_redact_template(self):
        e = Engine(EngineSettings(redact_template="[{type}]"))
        self.assertEqual(e.process("mail a.b@contoso.de", "redact").output, "mail [EMAIL]")

    def test_type_modes_override(self):
        s = EngineSettings(type_modes={"SECRET": "redact", "IPV4": "keep"})
        e = Engine(s)
        out = e.process("password: Geheim123 host 10.1.2.3", "pseudonymize").output
        self.assertEqual(out, "password: [REDACTED] host 10.1.2.3")

    def test_allowlists(self):
        sur = SurrogateSettings(allow_ip_ranges=["10.1.0.0/16"])
        e = Engine(EngineSettings(surrogate=sur, allow_terms={"geheimprojekt"}))
        out = e.process("10.1.2.3 10.2.2.3 github.com GeheimProjekt", "pseudonymize").output
        self.assertTrue(out.startswith("10.1.2.3 "))
        self.assertNotIn("10.2.2.3", out)
        self.assertIn("github.com", out)

    def test_custom_replacement_used_in_domain(self):
        ctx = DetectorContext(custom_terms=[{"term": "Contoso", "type": "ORG", "replacement": "Contoso"}])
        sur = SurrogateSettings(custom_replacements={"contoso": "Contoso"})
        e = Engine(EngineSettings(context=ctx, surrogate=sur))
        out = e.process("Contoso GmbH, www.contoso.de, info@contoso.de", "pseudonymize").output
        self.assertEqual(out, "Contoso GmbH, www.contoso.de, info@contoso.de")
        self.assertEqual(e.revert(out).output, "Contoso GmbH, www.contoso.de, info@contoso.de")

    def test_json_stays_valid(self):
        doc = {"server": {"host": "db01.contoso.local", "ip": "10.20.30.40", "password": "Sup3r\"Secret\\x"},
               "admins": ["j.hartmann@contoso.com"], "key": PEM_HEAD + "\nMIIEabc+/=\n" + PEM_TAIL}
        text = json.dumps(doc, indent=2)
        out = self.e.process(text, "pseudonymize").output
        parsed = json.loads(out)
        self.assertEqual(set(parsed), set(doc))
        self.assertNotEqual(parsed["server"]["password"], doc["server"]["password"])
        self.assertEqual(json.loads(self.e.revert(out).output), doc)

    def test_yaml_stays_valid(self):
        text = ("db:\n  host: pg.kunde.local\n  user: app\n  password: 'Geh:eim#1'\n"
                "  ip: 192.168.10.5\nnotify:\n  - admin@kunde.de\n  - m.muster@kunde.de\n")
        out = self.e.process(text, "pseudonymize").output
        parsed = yaml.safe_load(out)
        self.assertEqual(set(parsed["db"]), {"host", "user", "password", "ip"})
        self.assertEqual(yaml.safe_load(self.e.revert(out).output), yaml.safe_load(text))

    def test_formats_of_surrogates(self):
        out = self.e.process("IBAN DE89 3704 0044 0532 0130 00 Karte 4111-1111-1111-1111 "
                             "MAC 00:1A:2B:3C:4D:5E Tel +49 561 1234567 "
                             "SID S-1-5-21-1004336348-1177238915-682003330-1105", "pseudonymize").output
        from clipcloak.core.textutil import iban_checksum_ok, luhn_ok
        iban = re.search(r"DE\d{2}(?: \d{4}){4} \d{2}", out).group(0)
        self.assertTrue(iban_checksum_ok(iban.replace(" ", "")))
        card = re.search(r"\d{4}-\d{4}-\d{4}-\d{4}", out).group(0)
        self.assertTrue(luhn_ok(card.replace("-", "")))
        self.assertTrue(card.startswith("4"))
        self.assertRegex(out, r"MAC 00:1A:2B:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}")
        self.assertRegex(out, r"Tel \+49 \d{3} \d{7}")
        self.assertRegex(out, r"S-1-5-21-\d+-\d+-\d+-1105")

    def test_secret_format_preserved(self):
        out = self.e.process("token " + GLPAT, "pseudonymize").output
        tok = out.split()[1]
        self.assertTrue(tok.startswith("glpat-"))
        self.assertEqual(len(tok), len(GLPAT))

    def test_vault_swap(self):
        v1, v2 = Vault("a"), Vault("b")
        e = Engine(vault=v1)
        o1 = e.process("10.1.2.3", "pseudonymize").output
        e.set_vault(v2)
        o2 = e.process("10.1.2.3", "pseudonymize").output
        self.assertNotEqual(o1, o2)
        self.assertEqual(e.revert(o2).output, "10.1.2.3")
        e.set_vault(v1)
        self.assertEqual(e.revert(o1).output, "10.1.2.3")

    def test_unicode_and_empty(self):
        self.assertEqual(self.e.process("", "pseudonymize").output, "")
        t = "Grüße 🙂 an jürgen.müller@contoso.de"
        out = self.e.process(t, "pseudonymize").output
        self.assertIn("🙂", out)
        self.assertEqual(self.e.revert(out).output, t)


class HtmlTest(unittest.TestCase):
    def test_html_consistent_with_text(self):
        e = Engine()
        html = ('<html><body><p>Mail an <a href="mailto:jonas.hartmann@contoso.com">'
                'jonas.<b>hartmann</b>@contoso.com</a> &amp; Server <span>10.88.10.10</span></p>'
                '<script>var x="10.88.10.10";</script></body></html>')
        text = "Mail an jonas.hartmann@contoso.com & Server 10.88.10.10"
        rt = e.process(text, "pseudonymize").output
        rh = process_html(html, lambda s: e.process(s, "pseudonymize"))
        self.assertNotIn("hartmann", rh.split("<script>")[0])
        self.assertNotIn("<script", rh)                   # scripts are dropped (never shown, would carry data)
        self.assertNotIn("10.88.10.10", rh)
        mail = rt.split()[2]
        self.assertIn(f"mailto:{mail}", rh)
        self.assertIn(rt.split()[-1], rh)
        back = process_html(rh, e.revert)
        self.assertIn("mailto:jonas.hartmann@contoso.com", back)

    def test_cf_html(self):
        cf = ("Version:0.9\r\nStartHTML:0000000105\r\nEndHTML:0000000200\r\nStartFragment:0000000141\r\n"
              "EndFragment:0000000164\r\n<html><body>x</body></html>")
        start = cf.index("<html>")
        cf = cf.replace("0000000105", f"{start:010d}")
        self.assertTrue(strip_cf_html(cf).startswith("<html>"))
        self.assertEqual(strip_cf_html("<p>x</p>"), "<p>x</p>")


if __name__ == "__main__":
    unittest.main()
