import unittest

from tests import helpers  # noqa: F401  (isolated dirs)
from clipcloak.core.detectors import DetectorContext
from clipcloak.core.engine import Engine, EngineSettings


def found(text, **ctx):
    s = EngineSettings()
    s.enabled_detectors.add("entropy") if ctx.pop("entropy", False) else None
    s.context = DetectorContext(**ctx)
    e = Engine(s)
    return [(f.type, f.text) for f in e.analyze(text)]


def types_of(text, **ctx):
    return {t for t, _ in found(text, **ctx)}


class NetworkDetectors(unittest.TestCase):
    def test_ipv4(self):
        self.assertIn(("IPV4", "10.88.10.10"), found("Server 10.88.10.10, ok"))
        self.assertIn(("IPV4", "10.0.0.0/8"), found("route 10.0.0.0/8 via x"))
        self.assertIn(("IPV4", "192.168.1.1"), found("http://192.168.1.1:8080/"))

    def test_ipv4_negatives(self):
        for t in ("Version 1.2.3.4", "v1.2.3.4", "mask 255.255.255.0", "1.2.3.4.5", "10.1.2.345"):
            self.assertNotIn("IPV4", types_of(t), t)

    def test_ipv6(self):
        self.assertIn(("IPV6", "2a01:4f8:1:2::abcd"), found("addr 2a01:4f8:1:2::abcd end"))
        self.assertIn(("IPV6", "fe80::1c2:3ff:fe44:5566"), found("fe80::1c2:3ff:fe44:5566%eth0"))
        self.assertIn(("IPV6", "2a01:4f8::/32"), found("net 2a01:4f8::/32"))
        for t in ("12:30:45", "std::vector", "a::b", "00:1A:2B:3C:4D:5E"):
            self.assertNotIn("IPV6", types_of(t), t)

    def test_mac(self):
        self.assertIn(("MAC", "00:1A:2B:3C:4D:5E"), found("MAC 00:1A:2B:3C:4D:5E"))
        self.assertIn(("MAC", "001a.2b3c.4d5e"), found("cisco 001a.2b3c.4d5e"))
        self.assertIn(("MAC", "00-1a-2b-3c-4d-5e"), found("win 00-1a-2b-3c-4d-5e"))

    def test_email(self):
        self.assertIn(("EMAIL", "j.hartmann@contoso.com"), found("an j.hartmann@contoso.com."))
        self.assertEqual(found("@app.route('/x')"), [])

    def test_domains(self):
        self.assertIn(("DOMAIN", "srv-dc01.contoso.local"), found("host srv-dc01.contoso.local ok"))
        self.assertIn(("DOMAIN", "Contoso.de"), found("Besuchen Sie Contoso.de!"))
        self.assertIn(("DOMAIN", "db.kunde.local"), found("postgres://u:p@db.kunde.local:5432/x"))
        self.assertIn(("DOMAIN", "api.contoso.io"), found("GET https://api.contoso.io/v1"))

    def test_domain_code_negatives(self):
        for t in ('logger.info("x")', "user.name = 1", "README.md", "setup.py", "threading.local()",
                  "System.IO", "System.Net.Http", "self.request.user.id", "item.id", "os.path.join",
                  "this.store.state", "datetime.date.today()", "config.yaml", "main.rs"):
            self.assertNotIn("DOMAIN", types_of(t), t)

    def test_file_ext_tld_in_url(self):
        self.assertIn(("DOMAIN", "example-shop.sh"), found("https://example-shop.sh/x"))

    def test_known_domains(self):
        self.assertIn(("DOMAIN", "vpn.kunde.intern"), found("vpn.kunde.intern", known_domains=["kunde.intern"]))

    def test_hostnames(self):
        self.assertIn(("HOSTNAME", "fileserver"), found(r"\\fileserver\share\x"))
        res = found("jhartmann@srv01:~$ ls")
        self.assertIn(("USERNAME", "jhartmann"), res)
        self.assertIn(("HOSTNAME", "srv01"), res)
        self.assertIn(("HOSTNAME", "web01"), found("[root@web01 ~]# id"))


class SecretDetectors(unittest.TestCase):
    def test_tokens(self):
        cases = {
            "glpat_abcdefghijklmnopqrst1234": "SECRET",
            "ghp_" + "a" * 36: "SECRET",
            "AKIA_BCDEFGHIJKLMNOP": "SECRET",
            "xoxb_1234567890-abcdefghij": "SECRET",
            "sk_proj-abcdefghijklmnopqrstuvwxyz": "SECRET",
        }
        for tok, typ in cases.items():
            self.assertIn((typ, tok), found(f"x {tok} y"), tok)

    def test_jwt_keeps_header(self):
        jwt = "ey_JhbGciOiJIUzI1NiJ9.ey_JzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv"
        e = Engine()
        f = [x for x in e.analyze("t " + jwt) if x.type == "SECRET"][0]
        self.assertEqual(f.meta["keep_prefix"], len("eyJhbGciOiJIUzI1NiJ9") + 1)

    def test_kv_formats(self):
        self.assertIn(("SECRET", "Geheim1!"), found('{"password": "Geheim1!", "user": "bob"}'))
        self.assertIn(("SECRET", "Geheim1!"), found("db:\n  password: Geheim1!\n  port: 5432"))
        self.assertIn(("SECRET", "Geheim1!"), found("export DB_PASSWORD='Geheim1!'"))
        self.assertIn(("SECRET", "abc123xyz"), found("apiKey = abc123xyz"))
        self.assertIn(("SECRET", "Geheim1!"), found("<password>Geheim1!</password>"))
        self.assertIn(("SECRET", "Geheim1!"), found('<add key="x" password="Geheim1!"/>'))
        self.assertIn(("SECRET", "Geheim1!"), found("Server=db;User Id=sa;Password=Geheim1!;"))
        self.assertIn(("SECRET", "Geheim1!"), found("mytool --password Geheim1! --verbose"))
        self.assertIn(("SECRET", "Geheim1!"), found("mysql -u root -pGeheim1! db"))
        self.assertIn(("SECRET", "Geheim1!"), found('$p = ConvertTo-SecureString "Geheim1!" -AsPlainText -Force'))
        self.assertIn(("SECRET", "secretvalue"), found("client_secret: secretvalue"))

    def test_kv_negatives(self):
        for t in ("password_length: 12", "password: ${DB_PASS}", "token_type: Bearer",
                  "passwordless: true", "secretName: my-secret", "password: <password>",
                  "auth: none", '"password": ""', "tokenizer: bert", "key: app",
                  "Authorization: Bearer"):
            self.assertNotIn("SECRET", types_of(t), t)

    def test_url_credentials(self):
        res = found("postgres://app:dbpass99@db.x.local/app")
        self.assertIn(("SECRET", "dbpass99"), res)
        self.assertIn(("USERNAME", "app"), res)

    def test_pem(self):
        pem = "-----BEGIN PRIVATE_KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdEFGH==\n-----END PRIVATE_KEY-----"
        res = found(pem)
        self.assertEqual(res[0][0], "PRIVATE_KEY")
        self.assertTrue(res[0][1].startswith("MIIE"))
        self.assertFalse(res[0][1].endswith("\n"))
        esc = '"key": "-----BEGIN RSA PRIVATE_KEY-----\\nMIIEabc\\nxyz=\\n-----END RSA PRIVATE_KEY-----"'
        self.assertEqual(found(esc)[0], ("PRIVATE_KEY", "MIIEabc\\nxyz="))
        self.assertEqual(found("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"), [])

    def test_entropy_optional(self):
        s = "Zx8Kq2Lm9Pw4Rt7Vy1Bn5Cd3Fg6Hj0"
        self.assertNotIn("SECRET", types_of(f"value {s}"))
        self.assertIn(("SECRET", s), found(f"value {s}", entropy=True))


class IdentityDetectors(unittest.TestCase):
    def test_iban(self):
        self.assertIn(("IBAN", "DE89 3704 0044 0532 0130 00"), found("IBAN DE89 3704 0044 0532 0130 00, ok"))
        self.assertIn(("IBAN", "DE89370400440532013000"), found("DE89370400440532013000"))
        self.assertNotIn("IBAN", types_of("DE89 3704 0044 0532 0130 01"))

    def test_card(self):
        self.assertIn(("CREDIT_CARD", "4111 1111 1111 1111"), found("Karte 4111 1111 1111 1111"))
        self.assertNotIn("CREDIT_CARD", types_of("4111 1111 1111 1112"))

    def test_phone(self):
        self.assertIn(("PHONE", "+49 561 1234567"), found("Tel. +49 561 1234567"))
        self.assertIn(("PHONE", "0561/123456"), found("Tel 0561/123456."))
        self.assertIn(("PHONE", "+49 (0)561 123-456"), found("Tel +49 (0)561 123-456"))
        for t in ("2024-01-15", "12.03.2024", "Build 20240115"):
            self.assertNotIn("PHONE", types_of(t), t)

    def test_sid(self):
        sid = "S-1-5-21-1004336348-1177238915-682003330-1105"
        self.assertIn(("SID", sid), found(sid))
        self.assertEqual(found("S-1-5-18"), [])

    def test_user_paths(self):
        self.assertIn(("USERNAME", "mhartmann"), found(r"C:\Users\mhartmann\Documents"))
        self.assertIn(("USERNAME", "mhartmann"), found(r'"C:\\Users\\mhartmann\\x"'))
        self.assertIn(("USERNAME", "jhartmann"), found("/home/jhartmann/.ssh/id_ed25519"))
        self.assertIn(("USERNAME", "anna"), found("/Users/anna/Library"))
        self.assertEqual(found(r"C:\Users\Public\x"), [])
        res = found(r"login CONTOSO\mhartmann ok")
        self.assertIn(("HOSTNAME", "CONTOSO"), res)
        self.assertIn(("USERNAME", "mhartmann"), res)
        self.assertEqual(found(r"NT AUTHORITY\SYSTEM"), [])
        self.assertEqual(found(r'"Hello\nWorld"'), [])

    def test_custom_terms(self):
        terms = [{"term": "Projekt Adler", "type": ""}, {"term": r"KD-\d{5}", "regex": True},
                 {"term": "Acme", "type": "ORG", "replacement": "Contoso"}]
        res = found("Projekt Adler für KD-12345 und ACME", custom_terms=terms)
        self.assertIn(("CUSTOM", "Projekt Adler"), res)
        self.assertIn(("CUSTOM", "KD-12345"), res)
        self.assertIn(("ORG", "ACME"), res)


if __name__ == "__main__":
    unittest.main()


class PublicKeyTokenTest(unittest.TestCase):
    def test_public_key_token_is_no_secret(self):
        from clipcloak.config import Config, engine_settings
        from clipcloak.core.engine import Engine
        from clipcloak.core.vault import Vault
        e = Engine(engine_settings(Config()), Vault("t"))
        text = "[[System.__Canon, System.Private.CoreLib, Version=10.0.0.0, PublicKeyToken=7cec85d7bea7798e]](x)"
        self.assertFalse([f for f in e.analyze(text) if f.type == "SECRET"])
        found = [f.text for f in e.analyze("x(password=S3cr3t!x)]") if f.type == "SECRET"]
        self.assertEqual(found, ["S3cr3t!x"])
