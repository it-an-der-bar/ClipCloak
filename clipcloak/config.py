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
           "redact_image", "screenshot", "toggle_watcher"]

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
        "redact_image": "Ctrl+Alt+I",
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
    "image": {                        # image redaction (detection needs the plugin)
        "faces": True,
        "nudity": True,               # exposed intimate body parts (NudeNet)
        "text": True,                 # OCR + the text detectors
        "codes": True,                # QR codes / barcodes
        "face_effect": "mosaic",      # black | mosaic | blur
        "nudity_effect": "black",
        "text_effect": "black",       # black is the only safe choice for text
        "code_effect": "black",
        "padding": 3,
        "watch": True,                # watcher offers "Redact image" for images
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
        "tracking_params": [],        # additional URL parameters to remove
    },
    "llm": {
        "enabled": False,
        "base_url": "http://localhost:11434/v1",
        "api_key": "",
        "model": "",
        "vision_model": "",
        "timeout": 60,
        "vision_timeout": 180,        # screenshot -> text (vision models are slow)
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
        "os_encryption": True,        # encrypt projects without passphrase with the account (Windows DPAPI)
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


def _diff(data: dict, base: dict) -> dict:
    """Only what differs from ``base`` (the file then follows later changes of the defaults)."""
    out = {}
    for k, v in data.items():
        b = base.get(k) if isinstance(base, dict) else None
        if isinstance(v, dict) and isinstance(b, dict):
            sub = _diff(v, b)
            if sub:
                out[k] = sub
        elif k not in (base or {}) or v != b:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    """Settings in layers: DEFAULTS < machine defaults < user config.yaml < policy.

    ``data`` is the effective result. Policy keys are locked: ``set`` ignores them and
    ``save`` never writes them into the user's file. Policy entries of ``lists.*``
    are added to the user's lists instead.
    """

    def __init__(self, path: Path | None = None, data: dict | None = None, system=None):
        from .policy import SystemConfig
        self.path = Path(path) if path else None
        self.system = system or SystemConfig()
        self.load_error = ""
        self._user = copy.deepcopy(data or {})
        self.data = self._effective(self._user)

    # ------------------------------------------------------------ layers
    def base(self) -> dict:
        """DEFAULTS plus machine defaults, with the policy applied (for "Restore defaults")."""
        from .policy import set_dotted
        base = copy.deepcopy(DEFAULTS)
        for k, v in self.system.defaults.items():
            set_dotted(base, k, v)
        return self._apply_policy(base)

    def _effective(self, user: dict) -> dict:
        from .policy import set_dotted
        eff = copy.deepcopy(DEFAULTS)
        for k, v in self.system.defaults.items():
            set_dotted(eff, k, v)
        eff = deep_merge(eff, user)
        return self._apply_policy(eff)

    def _apply_policy(self, data: dict) -> dict:
        from .policy import get_dotted, set_dotted
        for k in self.system.locked_keys():
            set_dotted(data, k, self.system.policy[k])
        for k, extra in self.system.additive().items():
            cur = get_dotted(data, k) or []
            set_dotted(data, k, list(extra) + [x for x in cur if x not in extra])
        return data

    def is_locked(self, dotted: str) -> bool:
        for k in self.system.locked_keys():
            if k == dotted or k.startswith(dotted + ".") or dotted.startswith(k + "."):
                return True
        return False

    def policy_entries(self, dotted: str) -> list:
        """Entries an administrator added to a ``lists.*`` setting."""
        return list(self.system.additive().get(dotted, []))

    @property
    def managed(self) -> bool:
        return bool(self.system.policy)

    def replace(self, data: dict) -> None:
        """Take a complete settings dict (settings dialog); the policy stays in force."""
        from .policy import del_dotted, get_dotted, set_dotted
        user = copy.deepcopy(data)
        for k in self.system.locked_keys():      # enforced values are not the user's choice
            prev = get_dotted(self._user, k, _MISSING)
            if prev is _MISSING:
                del_dotted(user, k)
            else:
                set_dotted(user, k, prev)
        for k, extra in self.system.additive().items():
            cur = get_dotted(user, k)
            if isinstance(cur, list):
                set_dotted(user, k, [x for x in cur if x not in extra])
        self._user = user
        self.data = self._effective(self._user)

    # ------------------------------------------------------------ files
    @classmethod
    def load(cls, path: Path, system=None) -> "Config":
        from .policy import SystemConfig
        if system is None:
            system = SystemConfig.load(DEFAULTS)
        path = Path(path)
        data: dict = {}
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text("utf-8")) or {}
                if not isinstance(data, dict):
                    data = {}
            except (OSError, yaml.YAMLError) as exc:
                log.error("cannot read config %s: %s", path, exc)
                import time
                backup = path.with_name(f"{path.stem}.broken-{time.strftime('%Y%m%d-%H%M%S')}.yaml")
                try:
                    path.replace(backup)
                except OSError:
                    backup = None
                cfg = cls(path, {}, system)
                cfg.load_error = f"{exc}" + (f"\n→ {backup}" if backup else "")
                return cfg
        return cls(path, data, system)

    def user_data(self) -> dict:
        """What goes into config.yaml: the user's own choices only."""
        from .policy import del_dotted, get_dotted, set_dotted
        base = copy.deepcopy(DEFAULTS)
        for k, v in self.system.defaults.items():
            set_dotted(base, k, v)
        own = copy.deepcopy(self.data)
        for k in self.system.locked_keys():      # keep the user's value, not the enforced one
            prev = get_dotted(self._user, k, _MISSING)
            if prev is _MISSING:
                set_dotted(own, k, get_dotted(base, k))
            else:
                set_dotted(own, k, prev)
        for k, extra in self.system.additive().items():
            cur = get_dotted(own, k) or []
            set_dotted(own, k, [x for x in cur if x not in extra])
        out = _diff(own, base)
        for k in self.system.locked_keys():
            if get_dotted(self._user, k, _MISSING) is _MISSING:
                del_dotted(out, k)
        out["version"] = CONFIG_VERSION
        return out

    def save(self) -> None:
        if not self.path:
            return
        self._user = self.user_data()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(self._user, allow_unicode=True, sort_keys=False), "utf-8")
        if self.path.exists():
            try:   # keep the previous version as config.yaml.bak
                os.replace(self.path, self.path.with_name(self.path.name + ".bak"))
            except OSError:
                pass
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

    def set(self, dotted: str, value) -> bool:
        """Change a setting. Returns False (and changes nothing) if it is locked by policy."""
        if self.is_locked(dotted):
            return False
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
        if dotted.startswith("lists."):
            self._apply_policy(self.data)
        return True


_MISSING = object()


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
        allow_domains={x.lower().strip(".") for x in lists.get("allow_domains") or [] if x}
        | wordlists.PUBLIC_TECH_DOMAINS,
        allow_ip_ranges=list(lists.get("allow_ip_ranges") or []),
        generic_labels=set(wordlists.GENERIC_LABELS) | {x.lower() for x in lists.get("generic_labels_extra") or []},
        custom_replacements=replacements,
        known_domains=set(known),
        extra_tlds=set(lists.get("extra_tlds") or []),
    )
    ctx = DetectorContext(known_domains=known, custom_terms=terms,
                          extra_tlds=set(lists.get("extra_tlds") or []),
                          options={"entropy_threshold": d["detectors"].get("entropy_threshold", 4.0),
                                   "generic_labels": set(lists.get("generic_labels_extra") or []),
                                   "allow_terms": set(lists.get("allow_terms") or []),
                                   "tracking_params": set(lists.get("tracking_params") or [])})
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
