"""Machine-wide defaults and enforced settings (policies) set by an administrator.

Sources, lowest to highest priority:

  defaults (the user can change them):
    <system dir>/defaults.yaml
    Windows registry  HKLM\\SOFTWARE\\Policies\\<org>\\<App>\\Recommended

  policy (enforced, locked in the UI):
    <system dir>/policy.yaml
    Windows registry  HKCU\\SOFTWARE\\Policies\\<org>\\<App>
    Windows registry  HKLM\\SOFTWARE\\Policies\\<org>\\<App>      (Group Policy / ADMX)

<system dir> is %ProgramData%\\<app> on Windows and /etc/<app> on Linux
(override: environment variable <APP>_SYSTEM_DIR).

YAML files use the same structure as config.yaml. Registry values are named
with the dotted setting key (``watcher.mode``, ``llm.base_url``,
``detectors.enabled.kv-secrets``); lists are REG_MULTI_SZ, a text with one entry
per line or ";" separated, or a subkey of that name whose values are the entries
(this is what ADMX list elements write). Custom terms are written as
``term`` or ``term|TYPE|replacement``.

Entries under ``lists.*`` in a policy are added to the user's lists (company
terms, known domains …) instead of locking them.
"""

from __future__ import annotations

import copy
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .meta import APP_DISPLAY_NAME, APP_NAME, APP_ORG

log = logging.getLogger(__name__)

ADDITIVE_PREFIX = "lists."
REG_BASE = rf"SOFTWARE\Policies\{APP_ORG}\{APP_DISPLAY_NAME}"


def system_dir() -> Path:
    override = os.environ.get(APP_NAME.upper().replace("-", "_") + "_SYSTEM_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData") / APP_NAME
    return Path("/etc") / APP_NAME


# ------------------------------------------------------------------ helpers
def flatten(d: dict, prefix: str = "", defaults: dict | None = None) -> dict[str, object]:
    """Nested dict -> {dotted key: leaf}. A dict counts as leaf where the default is not a dict."""
    out: dict[str, object] = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        dflt = defaults.get(k) if isinstance(defaults, dict) else None
        if isinstance(v, dict) and (dflt is None or isinstance(dflt, dict)):
            out.update(flatten(v, key + ".", dflt if isinstance(dflt, dict) else {}))
        else:
            out[key] = v
    return out


def default_for(dotted: str, defaults: dict):
    cur = defaults
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


# settings that are mappings with free keys: detector ids, finding types
FREEFORM = {"detectors.enabled": bool, "processing.type_modes": str}


def known_key(dotted: str, defaults: dict) -> bool:
    """Dotted key exists in the defaults or is an entry of a FREEFORM mapping."""
    parent = dotted.rsplit(".", 1)[0] if "." in dotted else ""
    if parent in FREEFORM:
        return True
    cur = defaults
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return not isinstance(cur, dict) or dotted in FREEFORM


def _split_list(text: str) -> list[str]:
    sep = "\n" if "\n" in text else ";"
    return [x.strip() for x in text.split(sep) if x.strip()]


def _term(entry) -> dict | None:
    if isinstance(entry, dict):
        return entry if entry.get("term") else None
    parts = [p.strip() for p in str(entry).split("|")]
    if not parts[0]:
        return None
    term = {"term": parts[0]}
    if len(parts) > 1 and parts[1]:
        term["type"] = parts[1].upper()
    if len(parts) > 2 and parts[2]:
        term["replacement"] = parts[2]
    return term


def coerce(dotted: str, value, defaults: dict):
    """Bring a registry/YAML value into the type of the default. Raises ValueError."""
    dflt = default_for(dotted, defaults)
    parent = dotted.rsplit(".", 1)[0] if "." in dotted else ""
    if dflt is None and parent in FREEFORM:
        dflt = FREEFORM[parent]()          # False / ""
    if dotted == "lists.custom_terms":
        items = value if isinstance(value, list) else _split_list(str(value))
        return [t for t in (_term(x) for x in items) if t]
    if isinstance(dflt, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        s = str(value).strip().lower()
        if s in ("1", "true", "yes", "on", "ja"):
            return True
        if s in ("0", "false", "no", "off", "nein", ""):
            return False
        raise ValueError(f"{dotted}: not a boolean: {value!r}")
    if isinstance(dflt, int):
        return int(value)
    if isinstance(dflt, float):
        return float(value)
    if isinstance(dflt, list):
        if isinstance(value, list):
            return [x for x in value if x not in (None, "")]
        return _split_list(str(value))
    if isinstance(dflt, dict):
        if not isinstance(value, dict):
            raise ValueError(f"{dotted}: expected a mapping")
        return value
    if isinstance(value, (dict, list)):
        raise ValueError(f"{dotted}: expected a single value")
    return "" if value is None else str(value)


# ------------------------------------------------------------------ sources
def _read_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.error("cannot read %s: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        log.error("%s: expected a mapping at the top level", path)
        return {}
    return data


def _read_registry(hive_name: str, subkey: str) -> dict[str, object]:
    """{dotted key: raw value} from one registry key (Windows only)."""
    if sys.platform != "win32":
        return {}
    import winreg
    hive = getattr(winreg, hive_name)
    out: dict[str, object] = {}
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return out
    with key:
        i = 0
        while True:
            try:
                name, val, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if name:
                out[name] = val
        i = 0
        while True:     # list policies written by ADMX <list>: subkey with numbered values
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            if "." not in sub:       # e.g. "Recommended"
                continue
            try:
                with winreg.OpenKey(key, sub) as sk:
                    items, j = [], 0
                    while True:
                        try:
                            n, v, _t = winreg.EnumValue(sk, j)
                        except OSError:
                            break
                        j += 1
                        items.append((n, v))
            except OSError:
                continue
            items.sort(key=lambda nv: (0, int(nv[0])) if str(nv[0]).isdigit() else (1, str(nv[0])))
            out[sub] = [v for _n, v in items if v not in (None, "")]
    return out


@dataclass
class SystemConfig:
    defaults: dict[str, object] = field(default_factory=dict)   # dotted -> value
    policy: dict[str, object] = field(default_factory=dict)     # dotted -> value (enforced)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return bool(self.policy or self.defaults)

    @classmethod
    def load(cls, app_defaults: dict, directory: Path | None = None, registry: bool = True) -> "SystemConfig":
        sc = cls()
        d = Path(directory) if directory else system_dir()
        layers_defaults = [(str(d / "defaults.yaml"), flatten(_read_yaml(d / "defaults.yaml"), "", app_defaults))]
        layers_policy = [(str(d / "policy.yaml"), flatten(_read_yaml(d / "policy.yaml"), "", app_defaults))]
        if registry:
            layers_defaults.append(("HKLM\\" + REG_BASE + "\\Recommended",
                                    _read_registry("HKEY_LOCAL_MACHINE", REG_BASE + "\\Recommended")))
            layers_policy.append(("HKCU\\" + REG_BASE, _read_registry("HKEY_CURRENT_USER", REG_BASE)))
            layers_policy.append(("HKLM\\" + REG_BASE, _read_registry("HKEY_LOCAL_MACHINE", REG_BASE)))
        for target, layers in ((sc.defaults, layers_defaults), (sc.policy, layers_policy)):
            for source, values in layers:
                if values:
                    sc.sources.append(source)
                for dotted, raw in values.items():
                    if dotted == "version":
                        continue
                    if not known_key(dotted, app_defaults):
                        sc.errors.append(f"{source}: unknown setting {dotted}")
                        continue
                    try:
                        val = coerce(dotted, raw, app_defaults)
                    except (TypeError, ValueError) as exc:
                        sc.errors.append(f"{source}: {exc}")
                        continue
                    if target is sc.policy and dotted.startswith(ADDITIVE_PREFIX) and dotted in target:
                        val = list(target[dotted]) + [x for x in val if x not in target[dotted]]
                    target[dotted] = val
        for e in sc.errors:
            log.warning("policy: %s", e)
        return sc

    # ----------------------------------------------------------------- queries
    def locked_keys(self) -> set[str]:
        return {k for k in self.policy if not k.startswith(ADDITIVE_PREFIX)}

    def additive(self) -> dict[str, list]:
        return {k: v for k, v in self.policy.items() if k.startswith(ADDITIVE_PREFIX) and isinstance(v, list)}


def set_dotted(data: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    cur = data
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = copy.deepcopy(value)


def get_dotted(data: dict, dotted: str, default=None):
    cur = data
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def del_dotted(data: dict, dotted: str) -> None:
    parts = dotted.split(".")
    cur = data
    for p in parts[:-1]:
        cur = cur.get(p) if isinstance(cur, dict) else None
        if not isinstance(cur, dict):
            return
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)
