import json
import re
import tempfile
import unittest
from pathlib import Path

from tests import helpers  # noqa: F401
from clipcloak import i18n
from clipcloak.config import ACTIONS, DEFAULTS, Config, engine_settings
from clipcloak.core.detectors import BUILTIN_DETECTORS
from clipcloak.core.entities import ALL_TYPES
from clipcloak.paths import resource_path

PKG = Path(__file__).resolve().parent.parent / "clipcloak"


class ConfigTest(unittest.TestCase):
    def test_load_save_merge(self):
        p = Path(tempfile.mkdtemp()) / "config.yaml"
        p.write_text("general:\n  mode: redact\nlists:\n  known_domains: [kunde.de]\n", "utf-8")
        cfg = Config.load(p)
        self.assertEqual(cfg.get("general.mode"), "redact")
        self.assertEqual(cfg.get("hotkeys.pseudonymize"), DEFAULTS["hotkeys"]["pseudonymize"])
        cfg.set("watcher.mode", "critical")
        cfg.save()
        self.assertEqual(Config.load(p).get("watcher.mode"), "critical")

    def test_broken_config_is_backed_up(self):
        p = Path(tempfile.mkdtemp()) / "config.yaml"
        p.write_text("general: [unclosed\n", "utf-8")
        cfg = Config.load(p)
        self.assertEqual(cfg.get("general.mode"), "pseudonymize")
        self.assertTrue(list(p.parent.glob("config.broken-*.yaml")))
        self.assertTrue(cfg.load_error)

    def test_old_config_keeps_llm_and_backup(self):
        p = Path(tempfile.mkdtemp()) / "config.yaml"
        p.write_text("llm:\n  enabled: true\n  base_url: http://llm.lab:8000/v1\n  api_key: sk-abc\n  model: qwen\n", "utf-8")
        cfg = Config.load(p)
        cfg.set("general.mode", "redact")
        cfg.save()
        again = Config.load(p)
        self.assertEqual((again.get("llm.base_url"), again.get("llm.api_key"), again.get("llm.model")),
                         ("http://llm.lab:8000/v1", "sk-abc", "qwen"))
        self.assertTrue(p.with_name("config.yaml.bak").exists())

    def test_engine_settings(self):
        cfg = Config(data={"lists": {"custom_terms": [{"term": "Contoso", "replacement": "Contoso"}],
                                     "known_domains": ["kunde.intern"]},
                           "detectors": {"enabled": {"phone": False}},
                           "ner": {"enabled": True}})
        s = engine_settings(cfg, project_terms=[{"term": "Adler"}], project_domains=["adler.local"])
        self.assertNotIn("phone", s.enabled_detectors)
        self.assertIn("ner", s.enabled_detectors)
        self.assertEqual(s.surrogate.custom_replacements, {"contoso": "Contoso"})
        self.assertEqual(set(s.context.known_domains), {"kunde.intern", "adler.local"})
        self.assertEqual(len(s.context.custom_terms), 2)


class I18nTest(unittest.TestCase):
    def test_same_keys(self):
        en = json.loads(resource_path("i18n", "en.json").read_text("utf-8"))
        de = json.loads(resource_path("i18n", "de.json").read_text("utf-8"))
        self.assertEqual(set(en), set(de))
        for k in en:
            self.assertEqual(set(re.findall(r"\{(\w+)\}", en[k])), set(re.findall(r"\{(\w+)\}", de[k])), k)

    def test_all_used_keys_exist(self):
        en = json.loads(resource_path("i18n", "en.json").read_text("utf-8"))
        used = set()
        for f in PKG.rglob("*.py"):
            used |= set(re.findall(r'\bt\("([a-z_.\-]+[a-z_])"', f.read_text("utf-8")))
        dynamic = {
            "action.": ACTIONS, "mode.": ["pseudonymize", "anonymize", "redact", "revert"],
            "watch.": ["off", "notify", "critical", "always"],
            "source.": ["hotkey", "tray", "watcher", "popup", "workbench", "cli", "screenshot", "file"],
            "typemode.": ["default", "pseudonymize", "anonymize", "redact", "keep"],
            "det.": [c.id for c in BUILTIN_DETECTORS] + ["learned-names"],
            "anonstyle.": ["realistic", "placeholder"], "tld.": ["keep", "example"],
            "llmverify.": ["off", "warn"], "nerlang.": ["auto", "de", "en", "both"],
            "wb.btn_tip.": ["pseudonymize", "anonymize", "redact", "revert"],
            "llmpurpose.": ["verify", "detect", "screenshot", "models", "chat"],
            "lists.": [k + s for k in ("known_domains", "allow_terms", "allow_domains", "allow_ip_ranges",
                                       "generic_labels_extra", "extra_tlds") for s in ("", "_help")],
        }
        for prefix, names in dynamic.items():
            used |= {prefix + n for n in names}
        used |= {"msg.nothing_found", "msg.nothing_reverted", "lists.terms_help"}
        missing = sorted(k for k in used if k not in en)
        self.assertEqual(missing, [])
        self.assertTrue(set(ALL_TYPES))

    def test_translate(self):
        i18n.init("de")
        self.assertEqual(i18n.t("mode.redact"), "Schwärzen")
        self.assertEqual(i18n.t("wb.n_findings", n=3), "3 Fund(e)")
        i18n.init("en")
        self.assertEqual(i18n.t("mode.redact"), "Redact")
        self.assertEqual(i18n.t("does.not.exist"), "does.not.exist")


if __name__ == "__main__":
    unittest.main()
