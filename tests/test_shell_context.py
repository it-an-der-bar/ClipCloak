"""Shell commands: file paths, package names and OS names are no findings."""

import unittest

from tests import helpers  # noqa: F401

from clipcloak.config import Config, engine_settings
from clipcloak.core.detectors.external import plausible_entity
from clipcloak.core.engine import Engine
from clipcloak.core.vault import Vault


def found(text):
    e = Engine(engine_settings(Config()), Vault("t"))
    return [(f.type, f.text) for f in e.analyze(text)]


class ShellContextTest(unittest.TestCase):
    def test_file_paths_are_no_kubernetes_refs(self):
        self.assertEqual(found("sh deploy/compose/start.sh --build"), [])
        self.assertEqual(found("cat app/values.yaml"), [])
        self.assertEqual(found("./deploy/acme/run"), [])
        # real references still count
        self.assertIn(("IDENTIFIER", "acme"), found("kubectl -n x rollout restart deploy/acme-shop"))
        self.assertIn(("IDENTIFIER", "acme"), found("deployment.apps/acme-shop restarted"))

    def test_package_names_are_no_domains(self):
        text = ("sudo apt install -y \\\n  docker-ce \\\n  docker-ce-cli \\\n  containerd.io \\\n"
                "  docker-buildx-plugin \\\n  docker-compose-plugin")
        self.assertEqual(found(text), [])
        self.assertEqual(found("dnf install foo.bar-tools"), [])
        # after the command, and URLs inside it, domains count again
        self.assertIn(("DOMAIN", "host.acme.de"), found("apt-get install -y curl && ping host.acme.de"))
        self.assertIn(("DOMAIN", "git.acme.de"), found("pip install git+https://git.acme.de/x/y.git"))

    def test_os_names_are_no_orgs(self):
        for name in ("Debian GNU/Linux", "Ubuntu Server", "Red Hat Enterprise Linux", "Rocky Linux 9"):
            text = f'NAME="{name}"'
            s = text.index(name)
            with self.subTest(name=name):
                self.assertIsNone(plausible_entity(text, s, s + len(name), "ORG", None))
        text = "Wir haben mit Acme Linux GmbH gesprochen"
        s = text.index("Acme")
        self.assertIsNotNone(plausible_entity(text, s, s + len("Acme Linux GmbH"), "ORG", None))


if __name__ == "__main__":
    unittest.main()


class HexStringTest(unittest.TestCase):
    KEY = "75d54631a04f5ebe9e94e43eaaae4e4409204dfce26f3f283134121c56319caa"

    def test_bare_hex_is_a_secret(self):
        self.assertEqual(found(self.KEY), [("SECRET", self.KEY)])
        self.assertIn(("SECRET", self.KEY[:32]), found("https://hooks.example.com/hook/" + self.KEY[:32]))
        e = Engine(engine_settings(Config()), Vault("t"))
        out = e.process(self.KEY, "pseudonymize").output
        self.assertRegex(out, r"^[0-9a-f]{64}$")
        self.assertNotEqual(out, self.KEY)
        self.assertEqual(e.revert(out).output, self.KEY)

    def test_public_hashes_stay(self):
        for text in ("image: nginx@sha256:" + self.KEY, "commit " + self.KEY[:40], self.KEY + "  debian-12.iso",
                     "sha256: " + self.KEY, "0" * 64, "digest: " + self.KEY):
            with self.subTest(text=text[:20]):
                self.assertEqual([f for f in found(text) if f[0] == "SECRET"], [])


class IpNeverSkippedTest(unittest.TestCase):
    def test_real_ip_in_a_surrogate_network_is_found(self):
        e = Engine(engine_settings(Config()), Vault("t"))
        outs = [e.process(f"host 192.168.{i}.10", "pseudonymize").output.split()[-1] for i in range(64)]
        net = outs[0].rsplit(".", 1)[0]
        real = net + ".53" if outs[0] != net + ".53" else net + ".54"
        self.assertEqual([(f.type, f.text) for f in e.analyze("- " + real)], [("IPV4", real)])
        # even an address that equals an earlier surrogate is still found
        self.assertEqual([f.text for f in e.analyze("ip " + outs[1])], [outs[1]])


class CommonNounTest(unittest.TestCase):
    """NER labels ordinary (often English) nouns in German text as ORG/LOCATION."""

    def check(self, text, name, typ):
        s = text.index(name)
        return plausible_entity(text, s, s + len(name), typ, None)

    def test_common_nouns_dropped(self):
        text = ("Siehe Roadmap. Meldungen über die Security Advisories. Plugins und Shell-Kommandos, "
                "Dependencies, Release-Binaries, Attestations, Diagnostic-Bundles, Diagnose-Dateien, "
                "die Chain und die Shell des Containers.")
        for name, typ in (("Roadmap", "LOCATION"), ("Security Advisories", "ORG"), ("Plugins", "LOCATION"),
                          ("Shell-Kommandos", "LOCATION"), ("Dependencies", "ORG"),
                          ("Release-Binaries", "LOCATION"), ("Attestations", "ORG"),
                          ("Diagnostic-Bundles", "LOCATION"), ("Diagnose-Dateien", "LOCATION"),
                          ("Chain", "LOCATION"), ("Shell des Containers", "ORG")):
            with self.subTest(name=name):
                self.assertIsNone(self.check(text, name, typ))

    def test_real_names_kept(self):
        text = ("Treffen in München und Kassel, Büro in Musterhausen bei Contoso. "
                "Die Stadtwerke Kassel und die Acme Maschinenbau GmbH, Sparkasse Hannover, "
                "Northwind Traders in Boston, Frankfurt am Main, Essen.")
        for name, typ in (("München", "LOCATION"), ("Kassel", "LOCATION"), ("Musterhausen", "LOCATION"),
                          ("Contoso", "ORG"), ("Stadtwerke Kassel", "ORG"), ("Acme Maschinenbau GmbH", "ORG"),
                          ("Sparkasse Hannover", "ORG"), ("Northwind Traders", "ORG"),
                          ("Boston", "LOCATION"), ("Frankfurt am Main", "LOCATION"), ("Essen", "LOCATION")):
            with self.subTest(name=name):
                self.assertIsNotNone(self.check(text, name, typ))
