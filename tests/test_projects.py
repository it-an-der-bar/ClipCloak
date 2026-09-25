import json
import tempfile
import unittest
from pathlib import Path

from tests import helpers  # noqa: F401
from clipcloak.core.engine import Engine
from clipcloak.core.history import History
from clipcloak.core.projects import ProjectError, ProjectStore, WrongPassphrase


class ProjectTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.store = ProjectStore(self.dir)

    def _use(self, prj, text):
        e = Engine(vault=prj.vault)
        return e, e.process(text, "pseudonymize")

    def test_plain_roundtrip(self):
        prj = self.store.create("Kunde X")
        e, r = self._use(prj, "10.1.2.3 admin@kunde-x.de m.muster@kunde-x.de")
        h = History()
        h.add(r, "test", prj.name)
        prj.history = h.to_list()
        prj.terms = [{"term": "Adler"}]
        self.store.save(prj)
        loaded = self.store.load("Kunde X")
        self.assertEqual(loaded.terms, prj.terms)
        self.assertEqual(len(loaded.history), 1)
        e2 = Engine(vault=loaded.vault)
        self.assertEqual(e2.revert(r.output).output, r.input)
        # new text in the loaded project uses the same pseudonyms
        self.assertEqual(e2.process("10.1.2.3", "pseudonymize").output, e.process("10.1.2.3", "pseudonymize").output)
        doc = json.loads(self.store.path_for("Kunde X").read_text())
        self.assertFalse(doc["encrypted"])

    def test_encrypted(self):
        prj = self.store.create("Geheim", "correct horse")
        _, r = self._use(prj, "password: Sup3rGeheim")
        self.store.save(prj)
        raw = self.store.path_for("Geheim").read_text()
        self.assertNotIn("Sup3rGeheim", raw)
        self.assertTrue(json.loads(raw)["encrypted"])
        with self.assertRaises(WrongPassphrase):
            self.store.load("Geheim", "wrong")
        with self.assertRaises(WrongPassphrase):
            self.store.load("Geheim")
        loaded = self.store.load("Geheim", "correct horse")
        self.assertEqual(Engine(vault=loaded.vault).revert(r.output).output, r.input)
        self.assertTrue(loaded.encrypted)

    def test_list_delete_duplicates(self):
        self.store.create("A")
        self.store.create("B", "pw")
        infos = {i.name: i.encrypted for i in self.store.list()}
        self.assertEqual(infos, {"A": False, "B": True})
        with self.assertRaises(ProjectError):
            self.store.create("A")
        self.store.delete("A")
        self.assertEqual([i.name for i in self.store.list()], ["B"])

    def test_history_without_originals(self):
        e = Engine()
        r = e.process("Server 10.1.2.3 ok", "pseudonymize")
        h = History(store_originals=False)
        entry = h.add(r, "test")
        self.assertNotIn("10.1.2.3", entry.input)
        self.assertIn("Server ", entry.input)
        self.assertNotIn("10.1.2.3", json.dumps(h.to_list()))


if __name__ == "__main__":
    unittest.main()
