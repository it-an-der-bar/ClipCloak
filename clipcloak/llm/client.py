"""Minimal OpenAI-compatible chat client (stdlib only)."""

from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from ..activity import detail, event

VERIFY_PROMPT = (
    "You check texts that were anonymised before being sent to an AI assistant. "
    "Find every remaining piece of information that could identify a real person, company, "
    "customer, host, network or credential: personal names, company or customer names, "
    "internal host names, domains, IP addresses, e-mail addresses, phone numbers, account "
    "numbers, passwords, API keys, tokens. Values in angle brackets like <IPV4_1>, [REDACTED] "
    "and the following already replaced values are safe and must NOT be reported: {safe}. "
    "Answer with JSON only: {{\"findings\": [{{\"text\": \"exact substring\", \"type\": "
    "\"PERSON|ORG|DOMAIN|HOSTNAME|IPV4|EMAIL|PHONE|SECRET|OTHER\", \"reason\": \"short\"}}]}}. "
    "Return {{\"findings\": []}} if nothing is left."
)
DETECT_PROMPT = (
    "Extract named entities from the user's text. Report only these types: {types}. "
    "PERSON = names of real people, ORG = company/organisation/customer names, "
    "LOCATION = cities, streets, addresses. Do not report product names, technologies, "
    "programming identifiers or generic words. Answer with JSON only: "
    "{{\"entities\": [{{\"text\": \"exact substring\", \"type\": \"PERSON\"}}]}}."
)
OCR_PROMPT = ("Transcribe all text visible in this image exactly as written, keeping line breaks "
              "and indentation. Output only the transcribed text, no comments.")


class LLMError(Exception):
    pass


@dataclass
class LLMSettings:
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""
    model: str = ""
    vision_model: str = ""
    timeout: float = 60
    verify_tls: bool = True
    ca_bundle: str = ""

    @classmethod
    def from_config(cls, d: dict) -> "LLMSettings":
        return cls(d.get("base_url", ""), d.get("api_key", ""), d.get("model", ""),
                   d.get("vision_model", ""), float(d.get("timeout", 60) or 60),
                   bool(d.get("verify_tls", True)), d.get("ca_bundle", ""))


def _p(purpose: str) -> str:
    from ..i18n import t
    return t("llmpurpose." + purpose)


def logging_level_warning() -> int:
    import logging
    return logging.WARNING


def extract_json(text: str):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    for opener, closer in (("{", "}"), ("[", "]")):
        s, e = text.find(opener), text.rfind(closer)
        if s != -1 and e > s:
            try:
                return json.loads(text[s:e + 1])
            except ValueError:
                continue
    raise LLMError("no JSON in LLM answer")


class LLMClient:
    def __init__(self, settings: LLMSettings):
        self.s = settings

    def _ctx(self):
        if not self.s.base_url.lower().startswith("https"):
            return None
        if not self.s.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if self.s.ca_bundle:
            return ssl.create_default_context(cafile=self.s.ca_bundle)
        return ssl.create_default_context()

    def _host(self) -> str:
        try:
            return urlparse(self.s.base_url).netloc or self.s.base_url
        except ValueError:
            return self.s.base_url

    def chat(self, messages: list, model: str | None = None, json_mode: bool = False,
             max_tokens: int | None = None, purpose: str = "chat") -> str:
        model = model or self.s.model
        event("log.llm_request", purpose=_p(purpose), model=model or "-", host=self._host())
        t0 = time.monotonic()
        try:
            out = self._chat(messages, model, json_mode, max_tokens)
        except LLMError as exc:
            event("log.llm_fail", logging_level_warning(), purpose=_p(purpose),
                  ms=int((time.monotonic() - t0) * 1000), err=str(exc))
            raise
        event("log.llm_ok", purpose=_p(purpose), ms=int((time.monotonic() - t0) * 1000), chars=len(out))
        return out

    def _chat(self, messages: list, model: str | None, json_mode: bool,
              max_tokens: int | None) -> str:
        url = self.s.base_url.rstrip("/") + "/chat/completions"
        payload = {"model": model or self.s.model, "messages": messages, "temperature": 0}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        headers = {"Content-Type": "application/json"}
        if self.s.api_key:
            headers["Authorization"] = "Bearer " + self.s.api_key
        req = urllib.request.Request(url, json.dumps(payload).encode("utf-8"), headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.s.timeout, context=self._ctx()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:300]
            if json_mode and exc.code in (400, 422) and "response_format" in body:
                return self._chat(messages, model, False, max_tokens)
            raise LLMError(f"HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LLMError(str(exc)) from exc
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected response format") from exc

    def list_models(self) -> list[str]:
        url = self.s.base_url.rstrip("/") + "/models"
        headers = {}
        if self.s.api_key:
            headers["Authorization"] = "Bearer " + self.s.api_key
        req = urllib.request.Request(url, headers=headers)
        event("log.llm_request", purpose=_p("models"), model="-", host=self._host())
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.s.timeout, context=self._ctx()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            event("log.llm_fail", logging_level_warning(), purpose=_p("models"),
                  ms=int((time.monotonic() - t0) * 1000), err=str(exc))
            raise LLMError(str(exc)) from exc
        models = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
        event("log.llm_models", n=len(models), ms=int((time.monotonic() - t0) * 1000))
        return models

    # ------------------------------------------------------------ tasks
    def transcribe_image(self, png: bytes) -> str:
        uri = "data:image/png;base64," + base64.b64encode(png).decode()
        msgs = [{"role": "user", "content": [
            {"type": "text", "text": OCR_PROMPT},
            {"type": "image_url", "image_url": {"url": uri}},
        ]}]
        text = self.chat(msgs, model=self.s.vision_model or self.s.model, purpose="screenshot")
        m = re.fullmatch(r"\s*```[\w-]*\n(.*?)\n?```\s*", text, re.S)
        return m.group(1) if m else text

    def verify(self, text: str, safe_values: list[str]) -> list[dict]:
        safe = ", ".join(json.dumps(v) for v in safe_values[:200]) or "(none)"
        msgs = [{"role": "system", "content": VERIFY_PROMPT.format(safe=safe)},
                {"role": "user", "content": text}]
        data = extract_json(self.chat(msgs, json_mode=True, purpose="verify"))
        items = data.get("findings", []) if isinstance(data, dict) else data
        out = []
        for it in items or []:
            if isinstance(it, dict) and isinstance(it.get("text"), str) and it["text"].strip():
                if it["text"] in text and it["text"] not in safe_values:
                    out.append({"text": it["text"], "type": str(it.get("type", "OTHER")),
                                "reason": str(it.get("reason", ""))})
        event("log.llm_verify_result", n=len(out))
        if out:
            detail("log.llm_verify_items", items="; ".join(f"{i['text']} ({i['type']}: {i['reason']})" for i in out))
        return out

    def detect(self, text: str, types: list[str]) -> list[dict]:
        msgs = [{"role": "system", "content": DETECT_PROMPT.format(types=", ".join(types))},
                {"role": "user", "content": text}]
        data = extract_json(self.chat(msgs, json_mode=True, purpose="detect"))
        items = data.get("entities", []) if isinstance(data, dict) else data
        out = []
        for it in items or []:
            if isinstance(it, dict) and isinstance(it.get("text"), str):
                typ = str(it.get("type", "")).upper()
                if typ in types and it["text"].strip():
                    out.append({"text": it["text"].strip(), "type": typ})
        event("log.llm_detect_result", n=len(out))
        return out
