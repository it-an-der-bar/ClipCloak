# ClipCloak

[Deutsch](README.de.md)

ClipCloak sits in the system tray (Windows and Linux) and cleans the clipboard before you
paste it into an AI chat, a ticket or a forum post. It can **redact**, **anonymise** or
**reversibly pseudonymise** the content, and it can **translate the pseudonyms back** when
you copy the answer.

```
Before  jonas.hartmann@contoso.com  srv-dc01.contoso.local  10.88.10.10/24  GW 10.88.10.1  password: S3cr3t!
After   yara.kirchner@pluwolul.com      srv-dc01.pluwolul.local 10.58.239.119/24 GW 10.58.239.1 password: J0iy9f!
```

## Features

- **Three modes**
  - *Pseudonymise*: consistent, format-preserving replacements that can be reversed.
  - *Anonymise*: realistic but irreversible replacements, or `<TYPE_n>` placeholders.
  - *Redact*: replaces each finding with `[REDACTED]` (configurable, `{type}` allowed).
- **Replacements that still make sense**
  - IP addresses keep their class. 10/8 stays in 10/8, 172.16/12, 192.168/16, CGNAT and link-local stay in their ranges, and public addresses stay public. IPv6 ULA, link-local and global keep their class too.
  - Subnets are preserved (prefix-preserving, Crypto-PAn style). Hosts of the same /24 (IPv4) or /64 (IPv6) end up in the same surrogate subnet. `.0/.1/.254/.255` and `::1` stay, so gateways and broadcast addresses remain recognisable. CIDR notations keep their prefix length.
  - Domains keep their structure and TLD. Generic labels such as `www`, `mail`, `vpn`, `srv` or `k8s` are kept. The same word gets the same pseudonym everywhere: in the e-mail domain, the host name, the NetBIOS domain `CONTOSO\user`, and a company name defined as a custom term.
  - E-mail addresses become plausible person names. `jonas.hartmann@` also teaches the tokens *Jonas* and *Hartmann*, so they are replaced in the text as well.
  - The following keep their format:
    - IBANs get a valid checksum.
    - Credit card numbers are Luhn-valid.
    - Phone numbers keep their country code and layout.
    - MAC addresses keep their vendor OUI (optional).
    - Windows SIDs keep the RID and get a consistent domain part.
    - Secrets keep their length, character classes and known prefixes (`glpat-`, `ghp_`, JWT header …).
  - JSON, YAML, XML, `.env` and code stay syntactically valid, including escaped strings and PEM blocks inside JSON.
- **Revert.** Copy the LLM answer and press the revert shortcut to get the original values back. This also works for:
  - IP addresses the LLM invented inside a known surrogate subnet (the mapping is a bijection)
  - words whose capitalisation the LLM changed
- **What is detected**
  - IPv4/IPv6 addresses and networks, MAC addresses, e-mail addresses, domains/FQDNs (with heuristics against code such as `logger.info` or `user.name`), UNC host names and shell prompts (`user@host:~$`)
  - user names in `C:\Users\…`, `/home/…` and `DOMAIN\user`, Windows SIDs, IBANs, credit cards, phone numbers
  - secrets:
    - token formats: GitLab, GitHub, AWS, Slack, OpenAI/Anthropic, Stripe, npm, PyPI, Docker, Vault, HF, JWT, Azure SAS
    - PEM private keys and certificates
    - key/value credentials in JSON, YAML, `.env`, INI, XML and connection strings
    - URL credentials, `curl -u`, `mysql -p`, `--password`, `ConvertTo-SecureString`
    - high-entropy strings (optional)
  - your own **custom terms** (literal or regex, with optional type or fixed replacement), known domains and allowlists
- **Optional NER plugin.** Free-form person and company names are found by a separate helper program with spaCy and the German/English models. It runs fully locally, and the main program stays small.
- **Optional LLM features** (OpenAI-compatible endpoint, e.g. vLLM, Ollama, LiteLLM):
  - *Screenshot → text*: a vision model transcribes an image from the clipboard, and the text is then processed.
  - *Check*: the already processed text is sent to the LLM, which lists possible leftovers. You can add them as custom terms with one click.
  - *Detector*: the LLM is used as an additional name/company detector. This sends the original text to your endpoint, so it is off by default.
- **Clipboard watcher** with four modes:
  - *off*
  - *notify*: a popup offers Pseudonymise, Anonymise, Redact or Details.
  - *critical automatically*: secrets, keys, IBANs and cards are processed immediately, other findings ask.
  - *always*
- **Workbench** with live highlighting, a findings table and right-click actions (allowlist or custom term).
- **History** with a side-by-side diff of every action.
- **Mapping overview**: what was replaced by what, with filter and CSV export.
- **Pseudonyms are persisted.** They are stored in the project *Standard* by default, so reverting still works after a restart. Further projects (e.g. per customer) can be created, optionally encrypted with a passphrase (AES-256-GCM, scrypt), and each project can have its own terms and known domains. *RAM only* has to be chosen explicitly and is marked as lost on exit.
- **HTML clipboard content** (Outlook, Teams, browser) is processed together with the text. RTF is dropped, so no unprocessed copy remains.
- **UI** in English and German.

## Installation

Download the binaries from the GitLab release page:

| File | Purpose |
|---|---|
| `clipcloak-vX.Y.Z-windows-x86_64.exe` | Windows program (no installation needed) |
| `clipcloak-vX.Y.Z-linux-x86_64` | Linux program (`chmod +x`) |
| `clipcloak-ner-…` | optional NER plugin; put it **next to** the program (found automatically) |

On Linux the binary needs glibc ≥ 2.36 (Debian 12, Ubuntu 24.04, Fedora 37 or newer) and the usual
Qt/X11 libraries. On Debian/Ubuntu install `libxcb-cursor0 libxkbcommon-x11-0 libegl1`.
On Wayland also install `wl-clipboard`. GNOME needs the *AppIndicator* extension to show tray icons.

## Usage

| Default shortcut | Action |
|---|---|
| `Ctrl+Alt+P` | pseudonymise clipboard |
| `Ctrl+Alt+A` | anonymise clipboard |
| `Ctrl+Alt+R` | redact clipboard |
| `Ctrl+Alt+U` | revert pseudonyms (restore originals) |
| `Ctrl+Alt+W` | open workbench |

The workbench has one button per action. The result is copied to the clipboard automatically;
the checkbox next to the buttons (or `general.workbench_auto_copy`) switches this off.

The language is set in the tray menu or the main window under **Sprache / Language**. After a change,
the program restarts itself.

All shortcuts are configurable, and additional actions can be bound: process with default mode,
screenshot → text, toggle watcher. The tray menu contains all actions plus the default mode,
the watcher mode, pause, projects, history, mappings and settings.

A typical LLM round trip:

1. Copy the config or log.
2. Press `Ctrl+Alt+P`.
3. Paste it into the chat.
4. Copy the answer.
5. Press `Ctrl+Alt+U`.
6. Paste the answer, which now contains your real values.

### Wayland

Wayland does not let applications register global shortcuts. Bind the following commands in
your desktop settings instead. KDE: *System Settings › Shortcuts › Custom Shortcuts*.
GNOME: *Settings › Keyboard › Custom Shortcuts*.

```
clipcloak --action pseudonymize
clipcloak --action anonymize
clipcloak --action redact
clipcloak --action revert
clipcloak --action workbench
```

The command forwards the action to the running instance, or starts it. With `wl-clipboard`
installed, reading and writing work everywhere. The watcher needs the data-control protocol,
which KDE Plasma and wlroots compositors (Sway, Hyprland …) provide but GNOME does not.

### Command line

```
clipcloak                              start the tray application
clipcloak --action ACTION              send an action to the running instance
clipcloak process [--mode M] [--project P] [--in F] [--out F]
clipcloak revert  --project P [--passphrase-env VAR] [--in F] [--out F]
clipcloak analyze [--in F]             findings as JSON
clipcloak projects                     list projects
```

`process`/`revert` read stdin and write stdout. On Windows use `--in`/`--out`, because the
GUI build has no standard input. Encrypted projects take the passphrase from the environment
variable given with `--passphrase-env`, or ask for it interactively.

## Files

*Process file …* (in the tray and in the main window's File menu) processes a whole text file in the background; 1 MB takes about a second. You choose the action, and the result is saved next to the source, e.g. `notes.pseudo.md`, keeping the encoding and line endings. Revert works the same way. The workbench can also load and save files.

## NER plugin

1. On the release page download `clipcloak-ner-vX.Y.Z-windows-x86_64.exe` (Windows) or `clipcloak-ner-vX.Y.Z-linux-x86_64` (Linux, then `chmod +x`). It contains spaCy and the German/English models (~120 MB).
2. Put it into the same folder as the program. The file name can stay as it is.
3. Go to Settings › NER plugin, tick *Enable NER*, click *Test* and save with OK. The tab shows whether the helper was found, and has buttons to open the release page and the program folder.

## NER plugin

1. On the release page download `clipcloak-ner-vX.Y.Z-windows-x86_64.exe` (Windows) or `clipcloak-ner-vX.Y.Z-linux-x86_64` (Linux, then `chmod +x`). It contains spaCy and the German/English models (~120 MB).
2. Put it into the same folder as the program. The file name can stay as it is.
3. Go to Settings › NER plugin, tick *Enable NER*, click *Test* and save with OK. The tab shows whether the helper was found, and has buttons to open the release page and the program folder.

## LLM

Settings › LLM:

1. Enter the URL, plus the API token if the endpoint needs one.
2. Click *Test connection & load models*. `/v1` is added automatically if it is missing.
3. Pick the text model and, optionally, the vision model from the drop-downs.
4. Choose the features you want.

## Configuration and data

| | Windows | Linux |
|---|---|---|
| Settings (`config.yaml`) | `%APPDATA%\clipcloak\` | `~/.config/clipcloak/` |
| Projects, log | `%LOCALAPPDATA%\clipcloak\` | `~/.local/share/clipcloak/` |

Everything can be changed in the settings dialog. The YAML file can also be edited by hand.
Unknown keys fall back to the defaults.

## Security notes

- Detection is heuristic. Always check the result (workbench/diff) before sharing sensitive material. For names without a fixed format, use custom terms, known domains, the NER plugin or the LLM check.
- The session mapping and the history live only in RAM. Projects write mappings, including original values and secrets, to disk. Without a passphrase the file is plain JSON (mode 0600 on Linux). With a passphrase it is encrypted, although the project *name* stays readable.
- Anonymised values are never written to a mapping file. For placeholders only keyed hashes are kept in RAM.
- Clipboard contents are never written to the log.
- *History: keep original text* can be switched off. The history then shows only masked originals.
- The LLM check only sends the already processed text. Screenshot → text sends the image. The LLM detector sends the original text, so only enable it for an endpoint you control.

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m clipcloak                    # run from source
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -p "test_*.py" -v
```

To use the NER plugin from source, run `pip install -r requirements-ner.txt`. It is then used
automatically via `python -m clipcloak.ner_helper`. To build binaries, see `.gitlab-ci.yml`.
The CI runs tests on every push and builds and releases on version tags `vX.Y.Z`, which must
match `clipcloak/__init__.py`.

### Renaming

The name is centralised in `clipcloak/meta.py`. `python tools/rename_app.py <newname> [DisplayName]`
renames the package, entry scripts, CI variables and documentation in one go.

## License

GPL-3.0-only, see [LICENSE](LICENSE). Qt for Python (PySide6) is used under the LGPL-3.0.
spaCy and its models (NER plugin) are MIT-licensed.
