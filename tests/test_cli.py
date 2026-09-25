import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clipcloak.meta import APP_NAME

ROOT = Path(__file__).resolve().parent.parent


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        pre = APP_NAME.upper().replace("-", "_")
        self.env = dict(os.environ, PYTHONPATH=str(ROOT), **{pre + "_CONFIG_DIR": tmp + "/c", pre + "_DATA_DIR": tmp + "/d"})

    def run_cli(self, *args, inp=""):
        return subprocess.run([sys.executable, "-m", APP_NAME, *args], input=inp.encode(), capture_output=True,
                              env=self.env, cwd=str(ROOT), timeout=120)

    def test_version(self):
        r = self.run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.decode().startswith(APP_NAME))

    def test_analyze(self):
        r = self.run_cli("analyze", inp="mail a.b@contoso.de ip 10.1.2.3")
        self.assertEqual(r.returncode, 0, r.stderr)
        types = [f["type"] for f in json.loads(r.stdout)]
        self.assertEqual(types, ["EMAIL", "IPV4"])

    def test_process_revert_with_project(self):
        from clipcloak.core.projects import ProjectStore
        store = ProjectStore(Path(self.env[APP_NAME.upper().replace("-", "_") + "_DATA_DIR"]) / "projects")
        store.create("cli-test", "pw")
        env_pw = dict(self.env, CC_PW="pw")
        text = "Server db.kunde.local 10.9.8.7 password: Geheim99\n"
        r = subprocess.run([sys.executable, "-m", APP_NAME, "process", "--project", "cli-test", "--passphrase-env", "CC_PW"],
                           input=text.encode(), capture_output=True, env=env_pw, cwd=str(ROOT), timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.decode()
        self.assertNotIn("Geheim99", out)
        r2 = subprocess.run([sys.executable, "-m", APP_NAME, "revert", "--project", "cli-test", "--passphrase-env", "CC_PW"],
                            input=out.encode(), capture_output=True, env=env_pw, cwd=str(ROOT), timeout=120)
        self.assertEqual(r2.stdout.decode(), text)
        self.assertEqual([h["action"] for h in store.load("cli-test", "pw").history], ["revert", "pseudonymize"])

    def test_revert_needs_project(self):
        r = self.run_cli("revert", inp="x")
        self.assertEqual(r.returncode, 2)

    def test_files(self):
        d = Path(tempfile.mkdtemp())
        (d / "in.txt").write_text("password: Geheim99", "utf-8")
        r = self.run_cli("process", "--mode", "redact", "--in", str(d / "in.txt"), "--out", str(d / "out.txt"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((d / "out.txt").read_text("utf-8"), "password: [REDACTED]")


if __name__ == "__main__":
    unittest.main()
