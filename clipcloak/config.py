"""Configuration defaults, loading/saving and conversion to engine settings."""

from __future__ import annotations

import copy
import logging
import os
from pathlib import Path

import yaml

from .core import wordlists
from .core.detectors import DetectorContext, builtin_detectors
from .core.engine import EngineSettings
from .core.entities import DEFAULT_CRITICAL
from .core.surrogates import SurrogateSettings

log = logging.getLogger(__name__)

CONFIG_VERSION = 1

ACTIONS = ["pseudonymize", "anonymize", "redact", "revert", "process", "workbench", "process_file",
           "screenshot", "toggle_watcher"]

DEFAULTS: dict = {
    "version": CONFIG_VERSION,
    "general": {
        "language": "auto",          # auto | en | de
        "mode": "pseudonymize",      # mode used by the "process" action
        "notify": True,              # tray notification after an action
        "start_minimized": True,
        "autostart": False,
        "history_size": 200,
        "history_store_originals": True,
        "workbench_auto_copy": True,  # workbench result goes to the clipboard
    },
    "hotkeys": {
        "pseudonymize": "Ctrl+Alt+P",
        "anonymize": "Ctrl+Alt+A",
        "redact": "Ctrl+Alt+R",
        "revert": "Ctrl+Alt+U",
        "process": "",
        "workbench": "Ctrl+Alt+W",
        "process_file": "",
        "screenshot": "",
        "toggle_watcher": "",
    },
    "watcher": {
        "mode": "off",               # off | notify | critical | always
        "action": "pseudonymize",    # used by "always"
        "critical_types": list(DEFAULT_CRITICAL),
        "critical_action": "pseudonymize",
        "notify_noncritical": True,  # "critical": popup for non-critical findings
        "popup_timeout": 12,
        "max_chars": 500_000,
    },
    "clipboard": {
        "backend": "auto",           # auto | qt | wl-clipboard
        "process_html": True,
    },
    "processing": {
        "anonymize_style": "realistic",   # realistic | placeholder
        "placeholder_template": "<{type}_{n}>",
        "redact_template": "[REDACTED]",
        "skip_known_surrogates": True,
        "type_modes": {},             # e.g. {PRIVATE_KEY: redact}
        "disabled_types": [],
    },
    "detectors": {
        "enabled": {d.id: d.default_enabled for d in builtin_detectors()} | {"learned-names": True},
        "keep_special_hosts": True,
        "mac_keep_oui": True,
        "tld_strategy": "keep",       # keep | example
        "entropy_threshold": 4.0,
    },
    "lists": {
        "custom_terms": [],           # {term, type, replacement, regex, case_sensitive}
        "known_domains": [],
        "allow_terms": [],
        "allow_domains": list(wordlists.DEFAULT_ALLOWLIST_DOMAINS),
        "allow_ip_ranges": [],
        "generic_labels_extra": [],
        "extra_tlds": [],
    },
    "llm": {
        "enabled": False,
        "base_url": "http://localhost:11434/v1",
        "api_key": "",
        "model": "",
        "vision_model": "",
        "timeout": 60,
        "verify_tls": True,
        "ca_bundle": "",
        "verify_output": "off",       # off | warn
        "detect": False,              # use the LLM as additional detector
        "detect_types": ["PERSON", "ORG"],
    },
    "ner": {
        "enabled": False,
        "helper_path": "",
        "language": "auto",           # auto | de | en | both
        "types": ["PERSON", "ORG"],
        "model_de": "de_core_news_sm",
        "model_en": "en_core_web_sm",
    },
    "project": {
        "last": "",                   # last project; "" = "Standard", "@ram" = RAM only
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    def __init__(self, path: Path | None = None, data: dict | None = None):
        self.path = Path(path) if path else None
        self.data = deep_merge(DEFAULTS, data or {})

    @classmethod
    def load(cls, path: Path) -> "Config":
        path = Path(path)
        data: dict = {}
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text("utf-8")) or {}
                if not isinstance(data, dict):
                    data = {}
            except (OSError, yaml.YAMLError) as exc:
                log.error("cannot read config %s: %s", path, exc)
                backup = path.with_suffix(".broken.yaml")
                try:
                    path.replace(backup)
                except OSError:
                    pass
                data = {}
        return cls(path, data)

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(self.data, allow_unicode=True, sort_keys=False), "utf-8")
        try:
            os.chmod(tmp, 0o600)   # holds the LLM API key
        except OSError:
            pass
        os.replace(tmp, self.path)

    # dotted access -------------------------------------------------------
    def get(self, dotted: str, default=None):
        cur = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted: str, value) -> None:
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value


def engine_settings(cfg: Config, project_terms: list | None = None,
                    project_domains: list | None = None) -> EngineSettings:
    d = cfg.data
    lists = d["lists"]
    terms = list(lists.get("custom_terms") or []) + list(project_terms or [])
    replacements = {}
    for t in terms:
        term, rep = (t.get("term") or "").strip(), (t.get("replacement") or "").strip()
        if term and rep and not t.get("regex") and " " not in term:
            replacements[term.lower()] = rep
    known = [x for x in (list(lists.get("known_domains") or []) + list(project_domains or [])) if x]
    sur = SurrogateSettings(
        keep_special_hosts=bool(d["detectors"].get("keep_special_hosts", True)),
        mac_keep_oui=bool(d["detectors"].get("mac_keep_oui", True)),
        tld_strategy=d["detectors"].get("tld_strategy", "keep"),
        allow_domains={x.lower().strip(".") for x in lists.get("allow_domains") or [] if x},
        allow_ip_ranges=list(lists.get("allow_ip_ranges") or []),
        generic_labels=set(wordlists.GENERIC_LABELS) | {x.lower() for x in lists.get("generic_labels_extra") or []},
        custom_replacements=replacements,
        known_domains=set(known),
        extra_tlds=set(lists.get("extra_tlds") or []),
    )
    ctx = DetectorContext(known_domains=known, custom_terms=terms,
                          extra_tlds=set(lists.get("extra_tlds") or []),
                          options={"entropy_threshold": d["detectors"].get("entropy_threshold", 4.0)})
    enabled = {k for k, v in (d["detectors"].get("enabled") or {}).items() if v}
    if cfg.get("ner.enabled"):
        enabled.add("ner")
    if cfg.get("llm.enabled") and cfg.get("llm.detect"):
        enabled.add("llm")
    p = d["processing"]
    return EngineSettings(
        enabled_detectors=enabled,
        disabled_types=set(p.get("disabled_types") or []),
        redact_template=p.get("redact_template") or "[REDACTED]",
        anonymize_style=p.get("anonymize_style", "realistic"),
        placeholder_template=p.get("placeholder_template") or "<{type}_{n}>",
        type_modes=dict(p.get("type_modes") or {}),
        skip_known_surrogates=bool(p.get("skip_known_surrogates", True)),
        allow_terms={x for x in lists.get("allow_terms") or [] if x},
        surrogate=sur,
        context=ctx,
    )
