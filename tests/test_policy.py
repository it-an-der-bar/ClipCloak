"""Central settings (defaults/policy), config layering and project protection."""

import base64
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from clipcloak.config import DEFAULTS, Config
from clipcloak.core.projects import ProjectError, ProjectStore
from clipcloak.policy import SystemConfig, coerce, known_key


def system(tmp: Path, defaults=None, policy=None) -> SystemConfig:
    if defaults is not None:
        (tmp / "defaults.yaml").write_text(yaml.safe_dump(defaults), "utf-8")
    if policy is not None:
        (tmp / "policy.yaml").write_text(yaml.safe_dump(policy), "utf-8")
    return SystemConfig.load(DEFAULTS, tmp, registry=False)


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_coerce_registry_values(self):
        self.assertIs(coerce("ner.enabled", 1, DEFAULTS), True)
        self.assertIs(coerce("ner.enabled", "false", DEFAULTS), False)
        self.assertEqual(coerce("llm.timeout", "90", DEFAULTS), 90)
        self.assertEqual(coerce("detectors.entropy_threshold", "4.5", DEFAULTS), 4.5)
        self.assertEqual(coerce("lists.known_domains", "a.local;b.local", DEFAULTS), ["a.local", "b.local"])
        self.assertEqual(coerce("lists.known_domains", ["a", "", "b"], DEFAULTS), ["a", "b"])
        self.assertEqual(coerce("lists.custom_terms", ["Contoso|ORG|Firma", "Projekt X"], DEFAULTS),
                         [{"term": "Contoso", "type": "ORG", "replacement": "Firma"}, {"term": "Projekt X"}])
        self.assertIs(coerce("detectors.enabled.kv-secrets", 0, DEFAULTS), False)
        with self.assertRaises(ValueError):
            coerce("ner.enabled", "maybe", DEFAULTS)

    def test_known_keys(self):
        self.assertTrue(known_key("watcher.mode", DEFAULTS))
        self.assertTrue(known_key("detectors.enabled.kv-secrets", DEFAULTS))
        self.assertTrue(known_key("processing.type_modes.PRIVATE_KEY", DEFAULTS))
        self.assertFalse(known_key("llm.nonsense", DEFAULTS))
        self.assertFalse(known_key("watcher", DEFAULTS))

    def test_layers_lock_and_save(self):
        sc = system(self.tmp,
                    defaults={"llm": {"base_url": "http://llm.corp:8000/v1", "timeout": 90}},
                    policy={"watcher": {"mode": "critical"}, "ner": {"enabled": True},
                            "lists": {"known_domains": ["corp.local"]}, "bogus": {"x": 1}})
        self.assertTrue(any("bogus.x" in e for e in sc.errors))
        path = self.tmp / "user" / "config.yaml"
        cfg = Config.load(path, system=sc)
        self.assertEqual(cfg.get("llm.base_url"), "http://llm.corp:8000/v1")     # machine default
        self.assertEqual(cfg.get("watcher.mode"), "critical")                    # enforced
        self.assertTrue(cfg.is_locked("watcher.mode"))
        self.assertTrue(cfg.is_locked("watcher"))                                # container of a locked key
        self.assertFalse(cfg.is_locked("llm.base_url"))
        self.assertFalse(cfg.set("watcher.mode", "off"))
        self.assertEqual(cfg.get("watcher.mode"), "critical")
        self.assertTrue(cfg.set("llm.timeout", 30))
        self.assertTrue(cfg.set("lists.known_domains", ["corp.local", "mine.local"]))
        cfg.save()
        saved = yaml.safe_load(path.read_text("utf-8"))
        self.assertEqual(saved["llm"], {"timeout": 30})              # only own choices
        self.assertNotIn("watcher", saved)                           # policy never written
        self.assertNotIn("ner", saved)
        self.assertEqual(saved["lists"]["known_domains"], ["mine.local"])   # admin entry stripped
        again = Config.load(path, system=sc)
        self.assertEqual(again.get("lists.known_domains"), ["corp.local", "mine.local"])
        self.assertEqual(again.get("llm.timeout"), 30)
        # without the policy the user's own values come back
        free = Config.load(path, system=SystemConfig())
        self.assertEqual(free.get("watcher.mode"), DEFAULTS["watcher"]["mode"])
        self.assertEqual(free.get("lists.known_domains"), ["mine.local"])
        self.assertEqual(free.get("llm.base_url"), DEFAULTS["llm"]["base_url"])

    def test_locked_key_keeps_users_previous_value(self):
        path = self.tmp / "config.yaml"
        path.write_text(yaml.safe_dump({"watcher": {"mode": "notify"}}), "utf-8")
        cfg = Config.load(path, system=system(self.tmp, policy={"watcher": {"mode": "always"}}))
        self.assertEqual(cfg.get("watcher.mode"), "always")
        cfg.replace(dict(cfg.data, general=dict(cfg.data["general"], notify=False)))
        self.assertEqual(cfg.get("watcher.mode"), "always")
        cfg.save()
        saved = yaml.safe_load(path.read_text("utf-8"))
        self.assertEqual(saved["watcher"]["mode"], "notify")
        self.assertIs(saved["general"]["notify"], False)

    def test_base_for_restore_defaults(self):
        cfg = Config(None, {}, system(self.tmp, defaults={"general": {"mode": "redact"}},
                                      policy={"llm": {"enabled": True}}))
        base = cfg.base()
        self.assertEqual(base["general"]["mode"], "redact")
        self.assertIs(base["llm"]["enabled"], True)


class FakeProtector:
    name = "dpapi"

    def protect(self, data: bytes) -> bytes:
        return b"W" + bytes(b ^ 0x5A for b in data)

    def unprotect(self, data: bytes) -> bytes:
        if not data.startswith(b"W"):
            raise OSError(13, "bad data")
        return bytes(b ^ 0x5A for b in data[1:])


class ProtectionTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_os_protected_project(self):
        store = ProjectStore(self.dir, protector=FakeProtector())
        prj = store.create("Kunde A")
        prj.vault.record("PERSON", "Jonas Hartmann", "Yara Kirchner")
        store.save(prj)
        raw = store.path_for("Kunde A").read_text("utf-8")
        self.assertNotIn("Hartmann", raw)
        info = store.list()[0]
        self.assertEqual(info.protection, "dpapi")
        self.assertTrue(info.encrypted)
        self.assertFalse(store.needs_passphrase("Kunde A"))
        loaded = store.load("Kunde A")
        self.assertEqual(loaded.protection, "dpapi")
        # another account (other protector) cannot open it
        with self.assertRaises(ProjectError):
            ProjectStore(self.dir, protector=None).load("Kunde A")

    def test_plain_project_is_upgraded(self):
        ProjectStore(self.dir).create("Alt")
        self.assertEqual(ProjectStore(self.dir).list()[0].protection, "none")
        store = ProjectStore(self.dir, protector=FakeProtector())
        prj = store.load("Alt")
        self.assertEqual(prj.protection, "none")                 # no upgrade requested
        prj = store.load("Alt", upgrade=True)
        self.assertEqual(prj.protection, "dpapi")
        self.assertEqual(store.list()[0].protection, "dpapi")

    def test_passphrase_wins(self):
        store = ProjectStore(self.dir, protector=FakeProtector())
        store.create("Geheim", passphrase="pw")
        self.assertTrue(store.needs_passphrase("Geheim"))
        self.assertEqual(store.load("Geheim", "pw").protection, "passphrase")


class TemplatesTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_admx_up_to_date(self):
        import subprocess
        r = subprocess.run([sys.executable, str(self.ROOT / "tools" / "make_admx.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_example_files_are_valid(self):
        sc = SystemConfig.load(DEFAULTS, self.ROOT / "packaging" / "examples", registry=False)
        self.assertEqual(sc.errors, [])
        self.assertEqual(sc.policy["watcher.mode"], "critical")
        self.assertIn("example.internal", sc.policy["lists.known_domains"])
        cfg = Config(None, {}, sc)
        self.assertEqual(cfg.get("general.language"), "de")          # from defaults.yaml
        self.assertTrue(cfg.is_locked("llm.base_url"))

    def test_license_rtf(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("mlr", self.ROOT / "tools" / "make_license_rtf.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rtf = mod.to_rtf("a {b} \\c\nÄ\n")
        self.assertTrue(rtf.startswith("{\\rtf1"))
        self.assertIn("a \\{b\\} \\\\c\\par", rtf)
        self.assertIn("\\u196?", rtf)
        self.assertEqual(rtf.count("{") - rtf.count("\\{"), rtf.count("}") - rtf.count("\\}"))

    def test_reg_example_keys_are_known(self):
        import re
        text = (self.ROOT / "packaging" / "examples" / "policy-example.reg").read_text("utf-8")
        for name in re.findall(r'^"([^"]+)"=', text, re.M):
            if not name.isdigit():
                self.assertTrue(known_key(name, DEFAULTS), name)
        for sub in re.findall(r"\\ClipCloak\\([^\]]+)\]", text):
            self.assertTrue(known_key(sub, DEFAULTS), sub)


@unittest.skipUnless(sys.platform == "win32", "Windows registry")
class RegistryTest(unittest.TestCase):
    def test_read_values_and_lists(self):
        import uuid
        import winreg
        from clipcloak.policy import _read_registry
        base = r"Software\clipcloak-test-" + uuid.uuid4().hex[:8]
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
                winreg.SetValueEx(k, "watcher.mode", 0, winreg.REG_SZ, "critical")
                winreg.SetValueEx(k, "ner.enabled", 0, winreg.REG_DWORD, 1)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\lists.known_domains") as k:
                winreg.SetValueEx(k, "2", 0, winreg.REG_SZ, "b.local")
                winreg.SetValueEx(k, "1", 0, winreg.REG_SZ, "a.local")
            raw = _read_registry("HKEY_CURRENT_USER", base)
            self.assertEqual(raw["watcher.mode"], "critical")
            self.assertEqual(raw["ner.enabled"], 1)
            self.assertEqual(raw["lists.known_domains"], ["a.local", "b.local"])
        finally:
            for sub in (base + r"\lists.known_domains", base):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except OSError:
                    pass


@unittest.skipUnless(sys.platform == "win32", "Windows DPAPI")
class DpapiTest(unittest.TestCase):
    def test_roundtrip(self):
        from clipcloak.core.osprotect import protector
        prot = protector()
        self.assertIsNotNone(prot)
        secret = base64.b64decode(base64.b64encode(bytes(range(32))))
        wrapped = prot.protect(secret)
        self.assertNotEqual(wrapped, secret)
        self.assertEqual(prot.unprotect(wrapped), secret)
        with self.assertRaises(OSError):
            prot.unprotect(wrapped[:-4] + b"xxxx")
        store = ProjectStore(Path(tempfile.mkdtemp()), protector=prot)
        store.create("dpapi-test")
        self.assertEqual(store.load("dpapi-test").protection, "dpapi")


if __name__ == "__main__":
    unittest.main()


class SystemFileTrustTest(unittest.TestCase):
    """Machine-wide policy files count only when only administrators can change them."""

    def test_permission_check(self):
        import os
        from clipcloak.policy import _read_yaml, trusted_system_file
        d = Path(tempfile.mkdtemp())
        p = d / "policy.yaml"
        p.write_text("llm:\n  enabled: true\n", "utf-8")
        if sys.platform == "win32":
            import subprocess
            from clipcloak.platform.winsec import admin_only_writable, is_admin_sid, security_info
            owner, aces = security_info(p)
            self.assertTrue(owner.startswith("S-1-"))
            self.assertTrue(aces)
            self.assertTrue(is_admin_sid("S-1-5-32-544"))
            self.assertFalse(is_admin_sid("S-1-1-0"))                       # Everyone
            before = admin_only_writable(p)
            subprocess.run(["icacls", str(p), "/grant", "*S-1-1-0:(W)"], check=True, capture_output=True)
            self.assertFalse(admin_only_writable(p))                        # everyone may write: never
            self.assertFalse(trusted_system_file(p))
            self.assertIsInstance(before, bool)
            return
        is_root = os.geteuid() == 0
        os.chmod(d, 0o755)
        os.chmod(p, 0o644)
        self.assertEqual(trusted_system_file(p), is_root)
        os.chmod(p, 0o666)                               # writable by everyone: never trusted
        self.assertFalse(trusted_system_file(p))
        os.chmod(p, 0o644)
        os.chmod(d, 0o777)                               # folder writable by everyone: file can be replaced
        self.assertFalse(trusted_system_file(p))
        self.assertEqual(_read_yaml(p, check_owner=True), {})
        self.assertEqual(_read_yaml(p), {"llm": {"enabled": True}})

    def test_missing_file_is_untrusted(self):
        from clipcloak.policy import trusted_system_file
        self.assertFalse(trusted_system_file(Path(tempfile.mkdtemp()) / "nope.yaml"))


class SealedApiKeyTest(unittest.TestCase):
    def test_api_key_sealed_on_disk(self):
        from clipcloak.core import osprotect
        from clipcloak.policy import SystemConfig
        old = osprotect._cached
        osprotect._cached = FakeProtector()
        try:
            path = Path(tempfile.mkdtemp()) / "config.yaml"
            path.write_text("llm:\n  api_key: sk-secret-123\n", "utf-8")     # written by an older version
            cfg = Config.load(path, system=SystemConfig())
            self.assertEqual(cfg.get("llm.api_key"), "sk-secret-123")
            cfg.set("llm.timeout", 30)
            cfg.save()
            raw = path.read_text("utf-8")
            self.assertNotIn("sk-secret-123", raw)
            bak = path.with_name(path.name + ".bak")
            self.assertFalse(bak.exists() and "sk-secret-123" in bak.read_text("utf-8"))
            self.assertIn("sealed:", raw)
            again = Config.load(path, system=SystemConfig())
            self.assertEqual(again.get("llm.api_key"), "sk-secret-123")
            again.save()                                   # stays sealed, no double sealing
            self.assertEqual(Config.load(path, system=SystemConfig()).get("llm.api_key"), "sk-secret-123")
            osprotect._cached = None                       # no protector here: not usable, no crash …
            blind = Config.load(path, system=SystemConfig())
            self.assertEqual(blind.get("llm.api_key"), "")
            blind.set("llm.timeout", 30)
            blind.save()                                   # … and not lost on the next save
            osprotect._cached = FakeProtector()
            self.assertEqual(Config.load(path, system=SystemConfig()).get("llm.api_key"), "sk-secret-123")
        finally:
            osprotect._cached = old
