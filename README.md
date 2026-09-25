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
- **Pseudonyms are persisted, encrypted.** They are stored in the project *Standard* by default, so reverting still works after a restart. On Windows every project file is encrypted with the user's Windows account (DPAPI, no passphrase needed); a project passphrase (AES-256-GCM, scrypt) can be added. Further projects (e.g. per customer) can be created, each with its own terms and known domains. *RAM only* has to be chosen explicitly and is marked as lost on exit.
- **Central management.** MSI for silent installation (GPO, ESET PROTECT, baramundi, Intune …), ADMX templates for Group Policy, machine-wide default and policy files. Enforced settings are locked in the UI.
- **HTML clipboard content** (Outlook, Teams, browser) is processed together with the text. RTF is dropped, so no unprocessed copy remains.
- **UI** in English and German.

## Installation

| File | Contents |
|---|---|
| `clipcloak-vX.Y.Z-windows-x86_64.msi` | Windows installer for all users (`C:\Program Files\ClipCloak`), program + NER plugin; for managed deployment see [Deployment](#deployment-windows) |
| `clipcloak-vX.Y.Z-windows-x86_64.zip` | Windows portable: folder with `clipcloak.exe`, NER plugin in `ner\`, ADMX templates and example policy files in `policies\`, README, license |
| `clipcloak-vX.Y.Z-linux-x86_64.tar.gz` | `clipcloak`, NER plugin `clipcloak-ner`, `.desktop` file, icon, example policy files, README, license (unpack with `tar xzf`, executable bits are kept) |
| `clipcloak-vX.Y.Z-linux-x86_64` | Linux program only, without the NER plugin |

The ZIP and tar.gz need no installation: unpack them anywhere and start the program. Keep the folder
together – on Windows the program needs its `_internal` folder, the NER plugin its `ner` folder.
The NER plugin only runs when it is enabled in the settings.

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

The language is set under Settings › General › Sprache / Language; the program then offers to restart.
Projects are switched, created and configured in the bar above the tabs of the main window, in the *Project* menu or in the tray.

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

The MSI (feature *NER*), the ZIP (folder `ner\`) and the tar.gz already contain the plugin. It contains spaCy and the German/English models and runs fully locally.

1. Go to Settings › NER plugin, tick *Enable NER*, click *Test* and save with OK. The tab shows whether the helper was found.
2. With the Linux program-only download, put `clipcloak-ner` from the tar.gz next to the program. The helper is found next to the program or in its subfolder `ner`; any other location can be set under *Helper program*.

## LLM

Settings › LLM:

1. Enter the URL, plus the API token if the endpoint needs one.
2. Click *Test connection & load models*. `/v1` is added automatically if it is missing.
3. Pick the text model and, optionally, the vision model from the drop-downs.
4. Choose the features you want.

Screenshot → text has its own timeout (default 180 s, *Timeout screenshot → text*), because vision
models often need much longer than text requests (default 60 s). The Log tab shows the timeout of each request.

## Configuration and data

| | Windows | Linux |
|---|---|---|
| Settings (`config.yaml`) | `%APPDATA%\clipcloak\` | `~/.config/clipcloak/` |
| Projects, log | `%LOCALAPPDATA%\clipcloak\` | `~/.local/share/clipcloak/` |
| Machine-wide defaults / policy | `%ProgramData%\clipcloak\` | `/etc/clipcloak/` |

Everything can be changed in the settings dialog. The YAML file can also be edited by hand.
It only contains what differs from the defaults; missing keys use the defaults.

## Deployment (Windows)

### Installation with GPO, ESET PROTECT, baramundi, Intune …

The MSI installs for all users (per machine, no user interaction, no reboot):

```
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn AUTOSTART=0 DESKTOPSHORTCUT=1
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn ADDLOCAL=Main        (without the NER plugin)
msiexec /x clipcloak-vX.Y.Z-windows-x86_64.msi /qn                      (uninstall)
```

| Property / feature | Meaning | Default |
|---|---|---|
| `AUTOSTART` | `1`: start for every user at logon (HKLM `…\Run`) | `1` |
| `DESKTOPSHORTCUT` | `1`: shortcut on the common desktop | `0` |
| Feature `Main` | program, start menu entry | always |
| Feature `NER` | NER plugin | installed |

- **Group Policy:** *Computer Configuration › Policies › Software Settings › Software installation*, package from a network share (assigned).
- **ESET PROTECT:** client task *Software Install* › *Install by direct package URL* (`http://…/…msi` or `file://\\server\share\…msi`). The task always installs MSI packages silently; msiexec switches cannot be set there, only the package's properties, e.g. `AUTOSTART=0`.
- **baramundi Management Suite:** create an application from the MSI (or with the command line above) and assign it with a job; to detect the installed version use the MSI product (upgrade code below) or the registry value `HKLM\SOFTWARE\it-an-der-bar\ClipCloak\Version`.
- **Updates:** install the newer MSI the same way; it replaces the old version (major upgrade, upgrade code `{F6A0337E-BD8E-448C-AEFF-A1E4D06678B7}`). Pass properties such as `AUTOSTART=0` again on every update.
- User settings, projects and logs stay in the users' profiles; uninstalling does not delete them.
- The Windows build is a folder build: nothing is unpacked to `%TEMP%` at start, which suits AppLocker and endpoint protection. If the CI has a code signing certificate (variables `SIGN_PFX_BASE64`, `SIGN_PFX_PASSWORD`), the programs and the MSI are signed.

### Central settings

Two levels, each from files and/or the registry:

- **Defaults** – the user can change them: `%ProgramData%\clipcloak\defaults.yaml` (Linux `/etc/clipcloak/defaults.yaml`) or registry values under `HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak\Recommended`.
- **Policy** – enforced, greyed out in the UI with the note "Managed by your administrator": `%ProgramData%\clipcloak\policy.yaml` (Linux `/etc/clipcloak/policy.yaml`), registry `HKCU\…` or `HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak` (HKLM wins).

The YAML files use the structure of `config.yaml`; examples are in `policies\examples\` of the ZIP
(`examples/` in the tar.gz). Registry values are named after the setting, e.g. `watcher.mode` (REG_SZ `critical`),
`ner.enabled` (DWORD `1`), `llm.base_url`. Lists are a subkey of that name with values `1`, `2`, … or REG_MULTI_SZ;
custom terms are written as `term` or `term|TYPE|replacement` – see `policy-example.reg`.

Policy entries under `lists` (custom terms, known domains, allowlists) are **added** to the users' own entries
and are always active, e.g. to give everyone the company's names and domains.

**Group Policy templates:** copy `policies\clipcloak.admx` and the folders `en-US`/`de-DE` from the ZIP into the
central store (`\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`) or `C:\Windows\PolicyDefinitions`.
The settings then appear under *Computer/User Configuration › Policies › Administrative Templates › ClipCloak*.
With ESET or baramundi without GPO, distribute `policy.yaml` to `%ProgramData%\clipcloak\` or the registry values instead.

At start the Log tab shows which central settings were loaded, and names unknown keys or invalid values.

## Security notes

- Detection is heuristic. Always check the result (workbench/diff) before sharing sensitive material. For names without a fixed format, use custom terms, known domains, the NER plugin or the LLM check.
- The session mapping and the history live only in RAM. Projects write mappings, including original values and secrets, to disk:
  - Windows: always encrypted (AES-256-GCM). The key is protected by DPAPI and bound to the user's Windows account, so other users, disk copies or backups cannot read the file. Older plain project files are converted when they are opened. (Can be switched off under Settings › General; not recommended.)
  - With a project passphrase (all systems) the key comes from the passphrase (scrypt) instead; this also protects against other programs running under the same account.
  - Linux without passphrase: readable JSON with mode 0600 – the project bar shows "NOT encrypted".
  - The project *name* stays readable in the file.
- LLM tokens set by policy are stored in the registry/policy file and can be read by the users.
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
automatically via `python -m clipcloak.ner_helper`. To build binaries, see `.gitlab-ci.yml`;
`python tools/package_release.py vX.Y.Z --dist dist` bundles them into the ZIP and tar.gz.
The CI runs tests on every push and builds and releases on version tags `vX.Y.Z`, which must
match `clipcloak/__init__.py`.

### Renaming

The name is centralised in `clipcloak/meta.py`. `python tools/rename_app.py <newname> [DisplayName]`
renames the package, entry scripts, CI variables and documentation in one go.

## License

GPL-3.0-only, see [LICENSE](LICENSE). Qt for Python (PySide6) is used under the LGPL-3.0.
spaCy and its models (NER plugin) are MIT-licensed.
