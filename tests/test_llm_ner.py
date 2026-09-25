import importlib.util
import json
import sys
import tempfile
import textwrap
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from tests import helpers  # noqa: F401
from clipcloak.core.detectors.external import LlmDetector, NerClient, NerDetector, find_ner_helper
from clipcloak.core.engine import Engine, EngineSettings
from clipcloak.llm.client import LLMClient, LLMSettings, extract_json


class _Handler(BaseHTTPRequestHandler):
    requests: list = []

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/v1/models"):
            self._send({"data": [{"id": "qwen"}, {"id": "llava"}]})
        else:
            self._send({}, 404)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.requests.append((self.headers.get("Authorization"), req))
        sys_msg = req["messages"][0]["content"]
        if isinstance(sys_msg, list):          # vision request
            content = "```\nServer 10.1.2.3\nuser: anna\n```"
        elif "Extract named entities" in sys_msg:
            content = json.dumps({"entities": [{"text": "Anna Schmidt", "type": "PERSON"},
                                               {"text": "Nowhere", "type": "PERSON"},
                                               {"text": "Globex", "type": "ORG"}]})
        else:
            content = "Here you go:\n```json\n" + json.dumps({"findings": [
                {"text": "Globex", "type": "ORG", "reason": "company"},
                {"text": "<IPV4_1>", "type": "IPV4"}]}) + "\n```"
        self._send({"choices": [{"message": {"content": content}}]})


class LLMTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.client = LLMClient(LLMSettings(base_url=f"http://127.0.0.1:{cls.srv.server_port}/v1",
                                           api_key="k123", model="qwen", vision_model="llava", timeout=5))

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_models(self):
        self.assertEqual(self.client.list_models(), ["qwen", "llava"])

    def test_verify(self):
        items = self.client.verify("Kunde Globex nutzt <IPV4_1>", ["<IPV4_1>"])
        self.assertEqual([i["text"] for i in items], ["Globex"])
        auth, req = _Handler.requests[-1]
        self.assertEqual(auth, "Bearer k123")
        self.assertEqual(req["temperature"], 0)

    def test_transcribe(self):
        self.assertEqual(self.client.transcribe_image(b"\x89PNG"), "Server 10.1.2.3\nuser: anna")
        _, req = _Handler.requests[-1]
        self.assertEqual(req["model"], "llava")
        self.assertTrue(req["messages"][0]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,"))

    def test_llm_detector(self):
        s = EngineSettings()
        s.enabled_detectors.add("llm")
        e = Engine(s, extra_detectors=[LlmDetector(self.client, ["PERSON", "ORG"])])
        found = {(f.type, f.text) for f in e.analyze("Anna Schmidt von Globex und nochmal Globex.")}
        self.assertEqual(found, {("PERSON", "Anna Schmidt"), ("ORG", "Globex")})
        out = e.process("Anna Schmidt von Globex", "pseudonymize").output
        self.assertNotIn("Anna", out)
        self.assertNotIn("Globex", out)

    def test_extract_json(self):
        self.assertEqual(extract_json('bla {"a": 1} bla'), {"a": 1})
        self.assertEqual(extract_json("```json\n[1,2]\n```"), [1, 2])


FAKE_HELPER = textwrap.dedent('''
    import json, sys
    for line in sys.stdin:
        req = json.loads(line)
        text = req["text"]
        ents = []
        for name, label in (("Erika Mustermann", "PER"), ("Globex AG", "ORG"), ("Berlin", "LOC")):
            i = text.find(name)
            if i >= 0:
                ents.append({"start": i, "end": i + len(name), "label": label})
        sys.stdout.write(json.dumps({"id": req["id"], "entities": ents}) + "\\n")
        sys.stdout.flush()
''')


SCRIPT = textwrap.dedent('''
    #!/usr/bin/env bash
    # RustDesk-Server erkennen und Konfiguration sichern
    RUSTDESK_DETECTED="nein"
    if has_cmd docker; then
      # Durchsuche alle Container nach rustdesk/rustdesk-server
      if docker ps --format '{{.Image}}' | grep -q 'rustdesk/rustdesk-server'; then
        RUSTDESK_DETECTED="ja"
      fi
    fi
    if has_cmd kubectl; then
      # Durchsuche alle Pods/Container-Images nach rustdesk/rustdesk-server
      RUSTDESK_SOURCE="k8s"
    fi
    echo "Deine Auswahl bitte:"
    read -r -p "Du willst fortfahren? (ACCEPT/abbrechen) " ANSWER
    case "$ANSWER" in
      ACCEPT) echo "Weiter" ;;
    esac
    # Ansprechpartner: Jonas Hartmann von der Contoso Solutions GmbH, Kassel
''')


class NerFilterTest(unittest.TestCase):
    def check(self, text, sub, typ, tokens=None):
        from clipcloak.core.detectors.external import plausible_entity
        s = text.index(sub)
        return plausible_entity(text, s, s + len(sub), typ, tokens)

    def test_rejects_code_and_words(self):
        t = 'RUSTDESK_DETECTED="nein" if has_cmd docker; Durchsuche; ACCEPT; esac; Deine Auswahl; Du; read'
        for sub, typ in (('RUSTDESK_DETECTED="nein', "PERSON"), ("if has_cmd docker", "ORG"), ("Durchsuche", "PERSON"),
                         ("ACCEPT", "ORG"), ("esac", "LOCATION"), ("Deine Auswahl", "ORG"), ("Du", "PERSON"),
                         ("read", "PERSON")):
            self.assertIsNone(self.check(t, sub, typ), sub)

    def test_keeps_real_names(self):
        t = "Jonas Hartmann, Anna-Lena Schmidt, Contoso Solutions GmbH, Siemens AG, Kassel"
        for sub, typ in (("Jonas Hartmann", "PERSON"), ("Anna-Lena Schmidt", "PERSON"),
                         ("Contoso Solutions GmbH", "ORG"), ("Siemens AG", "ORG"), ("Kassel", "LOCATION")):
            self.assertIsNotNone(self.check(t, sub, typ), sub)

    def test_person_trimmed_with_pos(self):
        t = "Contact John Smith at Globex Corporation"
        sub = "John Smith at Globex Corporation"
        s = t.index(sub)
        words = [("John", "PROPN"), ("Smith", "PROPN"), ("at", "ADP"), ("Globex", "PROPN"), ("Corporation", "PROPN")]
        toks, pos = [], s
        for w, p in words:
            i = t.index(w, pos)
            toks.append({"s": i, "e": i + len(w), "pos": p, "stop": w == "at"})
            pos = i + len(w)
        from clipcloak.core.detectors.external import plausible_entity
        r = plausible_entity(t, s, s + len(sub), "PERSON", toks)
        self.assertEqual(t[r[0]:r[1]], "John Smith")


class NerTest(unittest.TestCase):
    def test_fake_helper_protocol(self):
        d = Path(tempfile.mkdtemp())
        script = d / "fake_ner.py"
        script.write_text(FAKE_HELPER, "utf-8")
        det = NerDetector([sys.executable, str(script)], types=("PERSON", "ORG"))
        s = EngineSettings()
        s.enabled_detectors.add("ner")
        e = Engine(s, extra_detectors=[det])
        text = "Erika Mustermann (Globex AG) aus Berlin"
        found = {(f.type, f.text) for f in e.analyze(text)}
        self.assertEqual(found, {("PERSON", "Erika Mustermann"), ("ORG", "Globex AG")})
        r = e.process(text, "pseudonymize")
        self.assertIn("AG", r.output)            # legal form kept
        self.assertNotIn("Globex", r.output)
        self.assertEqual(e.revert(r.output).output, text)
        det.client.close()

    def test_helper_lookup_configured(self):
        self.assertIsNone(find_ner_helper("/does/not/exist"))
        self.assertEqual(find_ner_helper(sys.executable), [sys.executable])

    @unittest.skipUnless(importlib.util.find_spec("spacy") and importlib.util.find_spec("de_core_news_sm"),
                         "spaCy/models not installed")
    def test_real_spacy_on_shell_script(self):
        det = NerDetector([sys.executable, "-m", "clipcloak.ner_helper"], types=("PERSON", "ORG"))
        try:
            found = {(f.type, f.text) for f in det.find(SCRIPT, None)}
        finally:
            det.client.close()
        self.assertEqual(found, {("PERSON", "Jonas Hartmann"), ("ORG", "Contoso Solutions GmbH")})

    @unittest.skipUnless(importlib.util.find_spec("spacy") and importlib.util.find_spec("de_core_news_sm"),
                         "spaCy/models not installed")
    def test_real_spacy_helper(self):
        client = NerClient([sys.executable, "-m", "clipcloak.ner_helper"], timeout=120)
        try:
            res = client.request({"text": "Jonas Hartmann arbeitet bei der Siemens AG in München.", "lang": "de"})
            labels = {e["label"] for e in res["entities"]}
            self.assertIn("PER", labels)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
