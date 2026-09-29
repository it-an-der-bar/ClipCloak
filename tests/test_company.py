"""Company names anchored on the legal form (no language model needed)."""

import unittest

from tests import helpers  # noqa: F401

from clipcloak.config import Config, engine_settings
from clipcloak.core.detectors.base import DetectorContext
from clipcloak.core.detectors.company import CompanyDetector
from clipcloak.core.engine import Engine
from clipcloak.core.vault import Vault


def names(text):
    return [f.text for f in CompanyDetector().find(text, DetectorContext())]


class CompanyTest(unittest.TestCase):
    def test_found(self):
        text = ("18/3 GmbH\n\nKölpertechnis GmbH\n\nSadisches Blankloppen GmbH & Co. KG\n"
                "Wir haben mit der Kölpertechnis GmbH gesprochen, Firma Müller-Lüdenscheidt GmbH, "
                "Bank für Sozialwirtschaft AG.\nRechnung (Contoso Ltd.) an Procter & Gamble Inc. und 1&1 Versatel GmbH;\n"
                "Kunde: Hartmann Bau UG (haftungsbeschränkt) & Co. KG, Globex Corp., Musterfirma e.K., "
                "Förderverein Musterstadt e.V.")
        self.assertEqual(names(text), [
            "18/3 GmbH", "Kölpertechnis GmbH", "Sadisches Blankloppen GmbH & Co. KG", "Kölpertechnis GmbH",
            "Müller-Lüdenscheidt GmbH", "Bank für Sozialwirtschaft AG", "Contoso Ltd.", "Procter & Gamble Inc.",
            "1&1 Versatel GmbH", "Hartmann Bau UG (haftungsbeschränkt) & Co. KG", "Globex Corp.",
            "Musterfirma e.K.", "Förderverein Musterstadt e.V."])

    def test_not_found(self):
        for text in ("die AG tagt morgen", "5 KG Mehl", "Azure SAS token", "Siemens AG", "iPhone SE",
                     "GmbH", "eine GmbH gründen", "xGmbH"):
            with self.subTest(text=text):
                self.assertEqual(names(text), [])

    def test_pseudonymise_and_revert(self):
        e = Engine(engine_settings(Config()), Vault("t"))
        text = "18/3 GmbH\n\nKölpertechnis GmbH\n\nSadisches Blankloppen GmbH & Co. KG"
        out = e.process(text, "pseudonymize").output
        for part in ("18/3", "Kölpertechnis", "Sadisches", "Blankloppen"):
            self.assertNotIn(part, out)
        self.assertRegex(out, r"^\d\d/\d GmbH\n\n\w+ GmbH\n\n\w+ \w+ GmbH & Co\. KG$")
        self.assertEqual(e.revert(out).output, text)


if __name__ == "__main__":
    unittest.main()
