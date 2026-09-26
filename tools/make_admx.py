"""Generate the Group Policy templates (ADMX/ADML) from the settings table.

    python tools/make_admx.py            # writes packaging/windows/policies/
    python tools/make_admx.py --check    # exit 1 if the files are out of date (tests/CI)

Every policy writes one registry value named like the setting
(HKLM/HKCU\\SOFTWARE\\Policies\\<org>\\<App>\\<dotted key>), which clipcloak/policy.py
reads. Lists are ADMX <list> elements (subkey with numbered values).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clipcloak.config import ACTIONS, DEFAULTS  # noqa: E402
from clipcloak.meta import APP_DISPLAY_NAME, APP_NAME, APP_ORG  # noqa: E402
from clipcloak.policy import REG_BASE, known_key  # noqa: E402

OUT = ROOT / "packaging" / "windows" / "policies"
SINCE = "0.1.9"          # first version that reads policies (fixed, so the files do not change per release)
LANGS = {"en-US": "en", "de-DE": "de"}
I18N = {code: json.loads((ROOT / APP_NAME / "resources" / "i18n" / f"{code}.json").read_text("utf-8"))
        for code in LANGS.values()}

CATEGORIES = {
    "general": ("General", "Allgemein"),
    "watcher": ("Clipboard watcher", "Zwischenablage-Überwachung"),
    "detectors": ("Detectors", "Erkennung"),
    "lists": ("Lists (added to the user's entries)", "Listen (ergänzen die Einträge des Benutzers)"),
    "llm": ("LLM", "LLM"),
    "ner": ("NER plugin", "NER-Plugin"),
    "image": ("Images", "Bilder"),
    "hotkeys": ("Shortcuts", "Tastenkürzel"),
}

ADDITIVE_EN = ("\n\nThe entries are added to the user's own entries and are always active; "
               "the user can add further entries but cannot remove these.")
ADDITIVE_DE = ("\n\nDie Einträge ergänzen die eigenen Einträge des Benutzers und sind immer aktiv; "
               "der Benutzer kann weitere hinzufügen, diese aber nicht entfernen.")
LOCK_EN = "\n\nIf configured, the user cannot change this setting. Setting: {key}"
LOCK_DE = "\n\nWenn konfiguriert, kann der Benutzer die Einstellung nicht ändern. Einstellung: {key}"


def choice(prefix):
    return lambda value, lang: I18N[lang][prefix + value]


# (dotted key, kind, category, en title, de title, en help, de help, extra)
# kind: bool | enum | text | decimal | list
P = [
    ("general.language", "enum", "general", "Language", "Sprache",
     "Language of the user interface.", "Sprache der Oberfläche.",
     {"choices": ["auto", "en", "de"],
      "labels": lambda v, lang: {"auto": {"en": "automatic", "de": "automatisch"}[lang],
                                 "en": "English", "de": "Deutsch"}[v]}),
    ("general.mode", "enum", "general", "Default mode", "Standardmodus",
     "Mode used by the action \"Process clipboard (default mode)\".",
     "Modus der Aktion \"Zwischenablage verarbeiten (Standardmodus)\".",
     {"choices": ["pseudonymize", "anonymize", "redact"], "labels": choice("mode.")}),
    ("general.notify", "bool", "general", "Notification after an action", "Benachrichtigung nach einer Aktion",
     "Show a tray notification after each action.", "Nach jeder Aktion eine Tray-Benachrichtigung zeigen.", {}),
    ("general.autostart", "bool", "general", "Start with the user session", "Mit der Benutzersitzung starten",
     "Start the program at logon (per user). The MSI property AUTOSTART=1 sets this up for all users instead.",
     "Programm bei der Anmeldung starten (pro Benutzer). Die MSI-Eigenschaft AUTOSTART=1 richtet das stattdessen "
     "für alle Benutzer ein.", {}),
    ("general.history_store_originals", "bool", "general", "History keeps original text",
     "Verlauf speichert Originaltext",
     "If disabled, the history (RAM, and projects with history) shows only masked originals.",
     "Wenn deaktiviert, zeigt der Verlauf (RAM und Projekte mit Verlauf) nur maskierte Originale.", {}),
    ("general.workbench_auto_copy", "bool", "general", "Workbench copies the result",
     "Werkbank kopiert das Ergebnis",
     "The workbench puts each result into the clipboard.", "Die Werkbank legt jedes Ergebnis in die Zwischenablage.",
     {}),
    ("project.os_encryption", "bool", "general", "Encrypt projects with the Windows account (DPAPI)",
     "Projekte mit dem Windows-Konto verschlüsseln (DPAPI)",
     "Projects without a passphrase are encrypted with a key that only the user's Windows account can use. "
     "Disabling this stores them as readable JSON.",
     "Projekte ohne Passphrase werden mit einem Schlüssel verschlüsselt, den nur das Windows-Konto des "
     "Benutzers verwenden kann. Deaktiviert werden sie als lesbares JSON gespeichert.", {}),
    ("processing.anonymize_style", "enum", "general", "Anonymisation style", "Art der Anonymisierung",
     "Realistic values or <TYPE_n> placeholders.", "Realistische Werte oder Platzhalter <TYP_n>.",
     {"choices": ["realistic", "placeholder"], "labels": choice("anonstyle.")}),
    ("processing.redact_template", "text", "general", "Redaction text", "Schwärzungstext",
     "Replacement text for \"Redact\"; {type} is replaced by the finding type.",
     "Ersatztext für \"Schwärzen\"; {type} wird durch den Fundtyp ersetzt.", {}),
    ("clipboard.process_html", "bool", "general", "Process HTML clipboard content",
     "HTML-Inhalte der Zwischenablage verarbeiten",
     "Process the HTML version (Outlook, Teams, browser) together with the text.",
     "Die HTML-Fassung (Outlook, Teams, Browser) zusammen mit dem Text verarbeiten.", {}),

    ("watcher.mode", "enum", "watcher", "Watcher mode", "Überwachungsmodus",
     "off: no watching. notify: popup when something sensitive is copied. critical automatically: secrets, "
     "keys, IBANs and cards are processed at once. always: everything copied is processed.",
     "aus: keine Überwachung. melden: Popup, wenn etwas Sensibles kopiert wird. kritisch automatisch: "
     "Secrets, Schlüssel, IBANs und Karten werden sofort verarbeitet. immer: alles Kopierte wird verarbeitet.",
     {"choices": ["off", "notify", "critical", "always"], "labels": choice("watch.")}),
    ("watcher.action", "enum", "watcher", "Action in mode \"always\"", "Aktion im Modus \"immer\"",
     "What the watcher does in mode \"always\".", "Was die Überwachung im Modus \"immer\" tut.",
     {"choices": ["pseudonymize", "anonymize", "redact"], "labels": choice("mode.")}),
    ("watcher.critical_action", "enum", "watcher", "Action for critical findings",
     "Aktion bei kritischen Funden",
     "What the watcher does with critical findings in mode \"critical automatically\".",
     "Was die Überwachung im Modus \"kritisch automatisch\" mit kritischen Funden tut.",
     {"choices": ["pseudonymize", "anonymize", "redact"], "labels": choice("mode.")}),
    ("watcher.notify_noncritical", "bool", "watcher", "Popup for non-critical findings",
     "Popup bei nicht kritischen Funden",
     "In mode \"critical automatically\": ask for other findings.",
     "Im Modus \"kritisch automatisch\": bei anderen Funden nachfragen.", {}),
    ("watcher.critical_types", "list", "watcher", "Critical finding types", "Kritische Fundtypen",
     "Types handled automatically in mode \"critical automatically\", e.g. PRIVATE_KEY, SECRET, IBAN, "
     "CREDIT_CARD. Replaces the user's selection.",
     "Typen, die im Modus \"kritisch automatisch\" sofort verarbeitet werden, z. B. PRIVATE_KEY, SECRET, IBAN, "
     "CREDIT_CARD. Ersetzt die Auswahl des Benutzers.", {"additive": False}),
]

for did in DEFAULTS["detectors"]["enabled"]:
    P.append((f"detectors.enabled.{did}", "bool", "detectors",
              "Detector: " + I18N["en"]["det." + did], "Erkennung: " + I18N["de"]["det." + did],
              "Enable or disable this detector.", "Diese Erkennung ein- oder ausschalten.", {}))

P += [
    ("lists.custom_terms", "list", "lists", "Custom terms", "Eigene Begriffe",
     "Company names, project names, internal host names … One entry per line: term, or term|TYPE|replacement "
     "(e.g. Contoso|ORG|Firma). TYPE is e.g. ORG, PERSON, HOSTNAME, CUSTOM.",
     "Firmennamen, Projektnamen, interne Hostnamen … Ein Eintrag pro Zeile: Begriff oder Begriff|TYP|Ersatz "
     "(z. B. Contoso|ORG|Firma). TYP ist z. B. ORG, PERSON, HOSTNAME, CUSTOM.", {"additive": True}),
    ("lists.known_domains", "list", "lists", "Known domains", "Bekannte Domains",
     "Own domains that are always replaced consistently, also in host names (e.g. corp.local, contoso.com).",
     "Eigene Domains, die immer einheitlich ersetzt werden, auch in Hostnamen (z. B. corp.local, contoso.com).",
     {"additive": True}),
    ("lists.allow_terms", "list", "lists", "Allowed terms", "Erlaubte Begriffe",
     "Terms that are never replaced.", "Begriffe, die nie ersetzt werden.", {"additive": True}),
    ("lists.allow_domains", "list", "lists", "Allowed domains", "Erlaubte Domains",
     "Domains that are never replaced (public services, vendors).",
     "Domains, die nie ersetzt werden (öffentliche Dienste, Hersteller).", {"additive": True}),
    ("lists.allow_ip_ranges", "list", "lists", "Allowed IP ranges", "Erlaubte IP-Bereiche",
     "Networks in CIDR notation that are never replaced (e.g. 8.8.8.0/24).",
     "Netze in CIDR-Schreibweise, die nie ersetzt werden (z. B. 8.8.8.0/24).", {"additive": True}),

    ("llm.enabled", "bool", "llm", "Enable LLM features", "LLM-Funktionen aktivieren",
     "Screenshot → text and the result check via an OpenAI-compatible endpoint.",
     "Screenshot → Text und Ergebnisprüfung über einen OpenAI-kompatiblen Endpunkt.", {}),
    ("llm.base_url", "text", "llm", "LLM endpoint URL", "LLM-Endpunkt (URL)",
     "OpenAI-compatible base URL, e.g. https://llm.corp.local/v1.",
     "OpenAI-kompatible Basis-URL, z. B. https://llm.corp.local/v1.", {}),
    ("llm.api_key", "text", "llm", "LLM API token", "LLM-API-Token",
     "Bearer token for the endpoint. Note: policy values in the registry can be read by the users.",
     "Bearer-Token für den Endpunkt. Hinweis: Richtlinienwerte in der Registry sind für die Benutzer lesbar.", {}),
    ("llm.model", "text", "llm", "Text model", "Textmodell", "Model for the result check and the detector.",
     "Modell für die Ergebnisprüfung und die Erkennung.", {}),
    ("llm.vision_model", "text", "llm", "Vision model", "Vision-Modell",
     "Model for screenshot → text. Empty: text model.", "Modell für Screenshot → Text. Leer: Textmodell.", {}),
    ("llm.timeout", "decimal", "llm", "Request timeout (s)", "Timeout für Anfragen (s)",
     "Timeout for text requests in seconds.", "Timeout für Textanfragen in Sekunden.", {"min": 5, "max": 600}),
    ("llm.vision_timeout", "decimal", "llm", "Timeout screenshot → text (s)", "Timeout Screenshot → Text (s)",
     "Timeout for screenshot → text in seconds; vision models need much longer.",
     "Timeout für Screenshot → Text in Sekunden; Vision-Modelle brauchen deutlich länger.",
     {"min": 10, "max": 3600}),
    ("llm.verify_tls", "bool", "llm", "Verify TLS certificate", "TLS-Zertifikat prüfen",
     "Verify the endpoint's certificate.", "Das Zertifikat des Endpunkts prüfen.", {}),
    ("llm.ca_bundle", "text", "llm", "CA bundle", "CA-Bundle",
     "Path of a PEM file with the CA certificates for the endpoint.",
     "Pfad einer PEM-Datei mit den CA-Zertifikaten für den Endpunkt.", {}),
    ("llm.verify_output", "enum", "llm", "Result check", "Ergebnisprüfung",
     "Check processed text with the LLM for leftovers.", "Verarbeiteten Text vom LLM auf Reste prüfen lassen.",
     {"choices": ["off", "warn"], "labels": choice("llmverify.")}),
    ("llm.detect", "bool", "llm", "LLM as detector", "LLM als Erkennung",
     "Sends the ORIGINAL text to the endpoint. Only enable for an endpoint you control.",
     "Sendet den ORIGINALTEXT an den Endpunkt. Nur für einen eigenen Endpunkt aktivieren.", {}),

    ("ner.enabled", "bool", "ner", "Enable NER plugin", "NER-Plugin aktivieren",
     "Find names of people and companies with the local NER plugin (installed with the MSI feature NER).",
     "Personen- und Firmennamen mit dem lokalen NER-Plugin finden (mit dem MSI-Feature NER installiert).", {}),
    ("ner.helper_path", "text", "ner", "NER helper path", "Pfad des NER-Helfers",
     "Only needed if the helper is not in the program folder or its ner subfolder.",
     "Nur nötig, wenn der Helfer nicht im Programmordner oder dessen Unterordner ner liegt.", {}),
    ("ner.language", "enum", "ner", "NER language", "NER-Sprache", "Language model(s) to use.",
     "Zu verwendende(s) Sprachmodell(e).",
     {"choices": ["auto", "de", "en", "both"], "labels": choice("nerlang.")}),
]

EFFECT_LABELS = {"black": ("black", "schwarz"), "mosaic": ("mosaic", "Mosaik"), "blur": ("blur", "weichzeichnen")}
eff = {"choices": ["black", "mosaic", "blur"],
       "labels": lambda v, lang: EFFECT_LABELS[v][0 if lang == "en" else 1]}
P += [
    ("image.faces", "bool", "image", "Detect faces", "Gesichter erkennen",
     "Detect faces in images (plugin, YuNet model, local).", "Gesichter in Bildern erkennen (Plugin, YuNet-Modell, lokal).", {}),
    ("image.face_effect", "enum", "image", "Effect for faces", "Effekt für Gesichter",
     "How detected faces are hidden.", "Wie erkannte Gesichter verdeckt werden.", eff),
    ("image.text", "bool", "image", "Detect sensitive text in images", "Sensiblen Text in Bildern erkennen",
     "OCR (plugin, local) plus the text detectors: IP, e-mail, secrets, custom terms …",
     "OCR (Plugin, lokal) plus die Texterkennungen: IP, E-Mail, Secrets, eigene Begriffe …", {}),
    ("image.text_effect", "enum", "image", "Effect for text", "Effekt für Text",
     "Only \"black\" is safe for text; pixelated or blurred text can often be reconstructed.",
     "Für Text ist nur \"schwarz\" sicher; verpixelter oder weichgezeichneter Text lässt sich oft zurückrechnen.", eff),
    ("image.codes", "bool", "image", "Detect QR codes and barcodes", "QR-Codes und Barcodes erkennen",
     "Detect QR codes and barcodes in images.", "QR-Codes und Barcodes in Bildern erkennen.", {}),
    ("image.code_effect", "enum", "image", "Effect for codes", "Effekt für Codes",
     "How detected codes are hidden.", "Wie erkannte Codes verdeckt werden.", eff),
    ("image.watch", "bool", "image", "Offer image redaction for copied images", "Bei kopierten Bildern Schwärzen anbieten",
     "The clipboard watcher shows a popup \"Redact image\" when an image is copied.",
     "Die Überwachung zeigt beim Kopieren eines Bildes ein Popup \"Bild schwärzen\".", {}),
]

for action in ACTIONS:
    P.append((f"hotkeys.{action}", "text", "hotkeys", "Shortcut: " + I18N["en"]["action." + action],
              "Tastenkürzel: " + I18N["de"]["action." + action],
              "Key combination such as Ctrl+Alt+P. Empty: no shortcut.",
              "Tastenkombination wie Strg+Alt+P (als Ctrl+Alt+P schreiben). Leer: kein Kürzel.", {}))


def pid(dotted: str) -> str:
    return "P_" + "".join(c if c.isalnum() else "_" for c in dotted)


def admx() -> str:
    ver = "SUPPORTED_" + SINCE.replace(".", "_")
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           "<!-- generated by tools/make_admx.py - do not edit -->",
           '<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
           'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" '
           'xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
           "  <policyNamespaces>",
           f'    <target prefix="{APP_NAME}" namespace="{APP_ORG.replace("-", "")}.Policies.{APP_DISPLAY_NAME}" />',
           "  </policyNamespaces>",
           '  <resources minRequiredRevision="1.0" />',
           "  <supportedOn>", "    <definitions>",
           f'      <definition name="{ver}" displayName="$(string.{ver})" />',
           "    </definitions>", "  </supportedOn>",
           "  <categories>",
           f'    <category name="C_{APP_NAME}" displayName="$(string.C_{APP_NAME})" />']
    for cat in CATEGORIES:
        out += [f'    <category name="C_{cat}" displayName="$(string.C_{cat})">',
                f'      <parentCategory ref="C_{APP_NAME}" />', "    </category>"]
    out += ["  </categories>", "  <policies>"]
    for key, kind, cat, *_rest, extra in P:
        n = pid(key)
        head = (f'    <policy name="{n}" class="Both" displayName="$(string.{n})" explainText="$(string.{n}_Help)" '
                f'key="{REG_BASE}"')
        if kind == "bool":
            out += [head + f' valueName="{key}">',
                    f'      <parentCategory ref="C_{cat}" />', f'      <supportedOn ref="{ver}" />',
                    '      <enabledValue><decimal value="1" /></enabledValue>',
                    '      <disabledValue><decimal value="0" /></disabledValue>', "    </policy>"]
            continue
        out += [head + f' presentation="$(presentation.{n})">',
                f'      <parentCategory ref="C_{cat}" />', f'      <supportedOn ref="{ver}" />', "      <elements>"]
        if kind == "enum":
            out.append(f'        <enum id="{n}" valueName="{key}" required="true">')
            for c in extra["choices"]:
                out += [f'          <item displayName="$(string.{n}_{c})">',
                        f"            <value><string>{escape(c)}</string></value>", "          </item>"]
            out.append("        </enum>")
        elif kind == "text":
            out.append(f'        <text id="{n}" valueName="{key}" maxLength="2048" />')
        elif kind == "decimal":
            out.append(f'        <decimal id="{n}" valueName="{key}" required="true" '
                       f'minValue="{extra["min"]}" maxValue="{extra["max"]}" />')
        elif kind == "list":
            out.append(f'        <list id="{n}" key="{REG_BASE}\\{key}" valuePrefix="" />')
        out += ["      </elements>", "    </policy>"]
    out += ["  </policies>", "</policyDefinitions>", ""]
    return "\n".join(out)


def adml(code: str) -> str:
    lang = LANGS[code]
    i = 0 if lang == "en" else 1
    ver = "SUPPORTED_" + SINCE.replace(".", "_")
    strings = {f"C_{APP_NAME}": APP_DISPLAY_NAME,
               ver: (f"{APP_DISPLAY_NAME} {SINCE} or later" if lang == "en"
                     else f"{APP_DISPLAY_NAME} {SINCE} oder neuer")}
    for cat, names in CATEGORIES.items():
        strings[f"C_{cat}"] = names[i]
    pres = []
    for key, kind, _cat, t_en, t_de, h_en, h_de, extra in P:
        n = pid(key)
        strings[n] = t_en if lang == "en" else t_de
        help_ = h_en if lang == "en" else h_de
        if extra.get("additive"):
            help_ += ADDITIVE_EN if lang == "en" else ADDITIVE_DE
        else:
            help_ += (LOCK_EN if lang == "en" else LOCK_DE).format(key=key)
        strings[n + "_Help"] = help_
        label = escape(strings[n])
        if kind == "enum":
            for c in extra["choices"]:
                strings[f"{n}_{c}"] = extra["labels"](c, lang)
            pres.append(f'      <presentation id="{n}"><dropdownList refId="{n}" noSort="true">{label}</dropdownList>'
                        "</presentation>")
        elif kind == "text":
            pres.append(f'      <presentation id="{n}"><textBox refId="{n}"><label>{label}</label></textBox>'
                        "</presentation>")
        elif kind == "decimal":
            pres.append(f'      <presentation id="{n}"><decimalTextBox refId="{n}">{label}</decimalTextBox>'
                        "</presentation>")
        elif kind == "list":
            pres.append(f'      <presentation id="{n}"><listBox refId="{n}">{label}</listBox></presentation>')
    desc = ("Central settings for " if lang == "en" else "Zentrale Einstellungen für ") + APP_DISPLAY_NAME
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           "<!-- generated by tools/make_admx.py - do not edit -->",
           '<policyDefinitionResources xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
           'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" '
           'xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
           f"  <displayName>{escape(APP_DISPLAY_NAME)}</displayName>",
           f"  <description>{escape(desc)}</description>",
           "  <resources>", "    <stringTable>"]
    for sid, text in strings.items():
        out.append(f'      <string id="{sid}">{escape(text)}</string>')
    out += ["    </stringTable>", "    <presentationTable>", *pres, "    </presentationTable>",
            "  </resources>", "</policyDefinitionResources>", ""]
    return "\n".join(out)


def files() -> dict[Path, str]:
    res = {OUT / f"{APP_NAME}.admx": admx()}
    for code in LANGS:
        res[OUT / code / f"{APP_NAME}.adml"] = adml(code)
    return res


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    for key, *_ in P:
        if not known_key(key, DEFAULTS):
            raise SystemExit(f"unknown setting in policy table: {key}")
    stale = []
    for path, text in files().items():
        cur = path.read_text("utf-8") if path.exists() else None
        if cur != text:
            stale.append(path)
            if "--check" not in argv:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, "utf-8", newline="\r\n")
    if "--check" in argv and stale:
        print("out of date: " + ", ".join(str(p.relative_to(ROOT)) for p in stale))
        return 1
    print(("written: " if stale else "up to date: ") + str(OUT.relative_to(ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
