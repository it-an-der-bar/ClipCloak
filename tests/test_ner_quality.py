"""Quality of the NER path (spaCy + plausibility filter), measured instead of case by case.

Runs only where spaCy and the models are installed (pip install -r requirements-ner.txt).
  * a small gold set of business mails and technical sentences: every person/company/place found,
    nothing else
  * the German and English UI texts and docs of this repository (no names except a few examples):
    at most a handful of findings, all of them real names
"""

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

from tests import helpers  # noqa: F401

HAVE_SPACY = importlib.util.find_spec("spacy") is not None
ROOT = Path(__file__).resolve().parent.parent

GOLD = [
 ("Hallo Frau Sabine Brückner, anbei das Angebot für die Firma Kölpertechnis GmbH in Kassel.",
  {("PERSON","Sabine Brückner"),("ORG","Kölpertechnis GmbH"),("LOCATION","Kassel")}),
 ("Herr Dr. Thomas Wendelin von der Stadtwerke Bielefeld GmbH hat den Termin auf Donnerstag verschoben.",
  {("PERSON","Thomas Wendelin"),("ORG","Stadtwerke Bielefeld GmbH")}),
 ("Bitte schick die Rechnung an Markus Oberhuber, Oberhuber Metallbau, Ringstraße 4, Rosenheim.",
  {("PERSON","Markus Oberhuber"),("LOCATION","Rosenheim")}),
 ("Die Migration für Northwind Traders läuft am Wochenende, Ansprechpartnerin ist Julia Kerschbaumer.",
  {("ORG","Northwind Traders"),("PERSON","Julia Kerschbaumer")}),
 ("Meeting with John Carpenter from Globex Corporation in Chicago next week.",
  {("PERSON","John Carpenter"),("ORG","Globex Corporation"),("LOCATION","Chicago")}),
 ("Neue Funktionen: Bisherige Läufe anzeigen, Letzte Änderungen exportieren, Standardwerte zurücksetzen.", set()),
 ("Die Pipeline baut Container-Images, pusht nach Harbor und deployt per ArgoCD auf den Cluster.", set()),
 ("Fehler beim Start: Die Konfigurationsdatei konnte nicht gelesen werden. Bitte Einstellungen prüfen.", set()),
 ("Kurzbefehle: Strg+Alt+P pseudonymisiert, Strg+Alt+U übersetzt zurück, Entf löscht den Bereich.", set()),
 ("Security Advisories und Roadmap findest du im Wiki; Diagnose-Dateien werden nach 30 Tagen gelöscht.", set()),
 ("Grüße aus Hamburg, Anna-Lena Petersen", {("LOCATION","Hamburg"),("PERSON","Anna-Lena Petersen")}),
 ("Der Kunde Brunnthaler Landtechnik aus Mühldorf am Inn meldet einen Ausfall.", {("LOCATION","Mühldorf am Inn")}),
 ("Updated the README, fixed the build on Windows and bumped the version to 1.4.2.", set()),
 ("Summary: Jörg Weißenbacher approved the change request; rollout starts Monday.", {("PERSON","Jörg Weißenbacher")}),
]


# the only names in the repository texts (examples, attribution) and the example cities
ALLOWED = {("PERSON", "Jörg Michael"), ("PERSON", "Jonas Hartmann"), ("PERSON", "Max Mustermann"),
           ("ORG", "Sozialwirtschaft AG"), ("ORG", "18/3 GmbH"), ("LOCATION", "München"), ("LOCATION", "Essen"),
           ("LOCATION", "Frankfurt"), ("LOCATION", "Boston")}


@unittest.skipUnless(HAVE_SPACY, "spaCy not installed")
class NerQualityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from clipcloak.config import Config, engine_settings
        from clipcloak.core.detectors.external import NerDetector
        from clipcloak.core.engine import Engine
        from clipcloak.core.vault import Vault
        s = engine_settings(Config())
        s.enabled_detectors.add("ner")
        cls.ner = NerDetector([sys.executable, "-m", "clipcloak.ner_helper"], "auto", ("PERSON", "ORG", "LOCATION"))
        cls.engine = Engine(s, Vault("t"))
        cls.engine.add_detector(cls.ner)

    @classmethod
    def tearDownClass(cls):
        cls.ner.client.close()

    def found(self, text):
        return {(f.type, f.text) for f in self.engine.analyze(text) if f.type in ("PERSON", "ORG", "LOCATION")}

    def test_gold_set(self):
        for text, expected in GOLD:
            with self.subTest(text=text[:50]):
                self.assertEqual(self.found(text), expected)

    def test_repository_texts(self):
        texts = []
        for lang in ("de", "en"):
            d = json.loads((ROOT / "clipcloak" / "resources" / "i18n" / f"{lang}.json").read_text("utf-8"))
            texts.append("\n".join(v for v in d.values() if isinstance(v, str)))
        for f in ("README.md", "README.de.md", "docs/SECURITY-AUDIT.md"):
            texts.append((ROOT / f).read_text("utf-8"))
        extra = set()
        for text in texts:
            for chunk in re.split(r"\n{2,}", text):
                if chunk.strip():
                    extra |= self.found(chunk) - ALLOWED
        self.assertEqual(extra, set())


if __name__ == "__main__":
    unittest.main()
