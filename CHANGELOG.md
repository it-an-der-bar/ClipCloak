# Changelog

## 0.1.29

- GitLab pipeline switched off (GitHub Actions builds the releases); it runs again when the CI/CD variable `GITLAB_BUILDS=on` is set in the GitLab project.
- **Custom terms of the project are visible and editable again:** *Settings › Lists › Custom terms* shows all terms in one list with a column *Applies to* – "all projects" (config) or "project X" (the project file, where *Add as custom term* puts them); terms set by the administrator are shown read-only. The project tab points there. In the workbench, right click on a CUSTOM finding › *Edit custom term …* opens the list with that term selected.

NER checked against measurements instead of single cases (`tests/test_ner_quality.py`, runs where spaCy is installed):
- **Places only from the gazetteer**: a LOCATION of the model is kept only when it is a known place (GeoNames: cities 15,000+ worldwide, 1,000+ in DE/AT/CH, countries, German states – ≈ 85,000 names). Nouns and product names the model calls a place ("Kurzbefehle", "Gesäß", "Hyprland", "Ollama") are gone.
- **Persons**: after a known first name the tagger's part of speech is no longer trusted ("Anna-Lena Petersen" is found although the model tags "Petersen" as a verb); first names that are everyday words ("Per", "Will", "May", "Mark") do not count as a first name.
- **Organisations**: no lists or arrows (",", "→", "…"), no versions/code ("Python 3.5.x", "Pool.alloc"), no possessives, no months, no single words of up to 3 letters ("Del"), no technical terms ("URL", "API", "stdout" …); ordinary words before a linking word are cut off ("Migration für Northwind Traders" → "Northwind Traders"); a town that is also an English word ("Root") does not make an organisation specific.
- Result: the German and English UI texts and docs of this repository (≈ 17,000 words): the model reports 1,001 entities, 11 are kept – all of them real names. Gold set of business mails and technical sentences: 16 of 16 names found, no false finding. English package documentation (≈ 90,000 words): 4,534 → 140, mostly real author names; what is left are single-word product names (Thinc, Typer, Cython) – add them to the allowlist if they bother you.

## 0.1.28

- `docs/SECURITY-AUDIT.md`: the security review of 0.1.27 – data flows, all findings with severity and status (fixed / open), accepted risks, verification. Linked from `SECURITY.md` and the README.
- NER: a person made only of ordinary words ("Bisherige Läufe", "Neue Funktionen") is no longer reported – such a name must start with a first name ("Max Mustermann") or contain a rare word ("Günter Kölpertech"). First-name list (≈ 36,000 names) from nam_dict by Jörg Michael (GNU FDL 1.2+).
- GitHub release workflow can be started by hand for an existing tag (*Actions › Release › Run workflow*, choose the tag); a second run replaces the assets of the release.

## 0.1.27

Security review before the public release, and GitHub builds.

- New detector **Company names with a legal form** (on, category organisations): the name before GmbH, AG, KG, GmbH & Co. KG, UG (haftungsbeschränkt), e.K., e.V., Ltd., Inc., Corp., S.A., B.V., Sp. z o.o. … is found without a language model – also invented names and names with digits ("18/3 GmbH", "Kölpertechnis GmbH", "Sadisches Blankloppen GmbH & Co. KG", "Bank für Sozialwirtschaft AG", "1&1 Versatel GmbH"). Articles/prepositions, lead words ("Firma", "Kunde:"), punctuation and line breaks end the name; ambiguous short forms (AG, SE, KG, SAS …) need a clear name ("5 KG Mehl", "die AG tagt" are no company); well-known public companies stay. Digits in the name get other digits (`18/3 GmbH` → `32/8 GmbH`). The NER plugin no longer reports a bare legal form ("GmbH & Co.") as organisation.
- **Machine-wide policy files are only read when only administrators can change them.** Before, any local user could put a `policy.yaml` into `%ProgramData%\clipcloak` and enforce settings for everyone (e.g. an LLM endpoint of his own). Now owner and write permissions of the file and its folder are checked (Windows: SYSTEM, TrustedInstaller, Administrators or a member; Linux: root, not writable by others); the MSI creates the folder with an ACL that only lets administrators write.
- **Linux: projects are encrypted with the desktop keyring** (Secret Service: GNOME Keyring, KWallet, KeePassXC) like with DPAPI on Windows – before they were readable JSON (0600). Existing plain projects are converted when opened. Without a keyring nothing changes ("NOT encrypted", passphrase possible); the keyring is tried again if it starts after the program.
- LLM API key in `config.yaml` sealed with the account (DPAPI / keyring). No backup copy with a plain key is kept.
- The clipboard watcher never sends text to the LLM detector (only explicit actions do). The workbench LLM check sends only the result, never the unprocessed input. A successful connection test no longer switches LLM features on.
- LLM client: redirects are refused (the API key would go to another host), only http/https, local endpoints bypass proxies from the environment, a warning for an API key over plain http to a remote host; error responses (which often echo the request text) are no longer written to the log file.
- HTML clipboard: comments (Office metadata such as the author), CDATA, processing instructions and scripts are dropped; *all* attribute values are processed (also unquoted ones, `aria-label`, `id`, `srcset` …), except pure formatting and embedded `data:` images.
- History with *keep original text* off: revert results, LLM-check warnings and entries loaded from a project are masked too; switching the option off also masks existing entries and saves the project at once.
- Restored originals are copied with the flags that keep them out of the Windows clipboard history and cloud clipboard and are marked as password for KDE Klipper.
- NER helper: only fixed paths next to the program are started (no wildcard names, no search of the current directory/PATH on Windows; a configured helper path must be absolute).
- Files are written with mode 0600 from the start (config, projects, log; umask 077), data folders 0700; the IPC socket lives in `$XDG_RUNTIME_DIR` on Linux.
- Passphrase projects: scrypt N = 2^17 (OWASP); existing files keep their parameters.
- Code signing: the certificate password is no longer passed on the command line.
- Code quality: `ruff` (pyflakes, pycodestyle, bugbear, pyupgrade, bandit rules) is clean and runs in CI.
- **GitHub Actions** (`.github/workflows/ci.yml`, `release.yml`) next to GitLab CI: lint and tests on every push, on a version tag the same packages (MSI, portable ZIP, tar.gz, policies ZIP) as GitHub release assets. Test data use no token-shaped literals (secret scanners would block the push). `SECURITY.md` added.
- Test data no longer point to a real region (phone area code, towns).

## 0.1.26

- Removed all real names from the program, the examples and the tests: the sample data now use the fictitious company *Contoso* (`contoso.com`, `CONTOSO\user`) and the person *Jonas Hartmann* (NER self-test, settings "Test", TLD example, README before/after example).

## 0.1.25

New defaults as shipped (existing settings of a user stay as they are – `config.yaml` only holds what was changed):
- Watcher **on**, mode *by category* (was *off*).
- Per category: tracking in links *always change*; secrets and keys, bank and card data *inform* (were *always change*); people, organisations/places, network, infrastructure names, key/certificate identifiers *inform*; custom terms *nothing* (was *inform*).
- Detector *infrastructure names* **off** by default (can be switched on in Settings › Detectors).
- Images: extra margin around faces 20 % (was 15 %).

## 0.1.24

- NER: **far fewer false positives on ordinary nouns.** The German model labels capitalised nouns and English loanwords in German text as places or organisations ("Roadmap", "Plugins", "Shell-Kommandos", "Dependencies", "Release-Binaries", "Attestations", "Diagnose-Dateien", "Chain", "Security Advisories", "Shell des Containers"). An ORG/LOCATION made only of frequent English/German words (also in hyphenated compounds and plurals) is dropped now.
  - Kept: known places (München, Kassel, Essen, Frankfurt am Main, Boston … – GeoNames: cities with 15,000+ inhabitants, in DE/AT/CH from 1,000), organisations with a legal form (… GmbH, AG, Inc.) or named after a place ("Stadtwerke Kassel", "Sparkasse Hannover"), and every name that is no common word (Contoso, Musterhausen, Northwind …). Known places are now also kept when the tagger marks them as nouns.
  - Word lists: the 120,000 most frequent English and German words (wordfreq, CC BY-SA 4.0) and place names (GeoNames, CC BY 4.0) in `resources/wordlists` (≈ 700 KB), built by `tools/make_wordlists.py`.
  - Measured on a German security policy with English terms: 11 of 11 false findings gone; persons, companies and places in the same text are still found.

## 0.1.23

- Windows portable download is now just **two EXEs**: `clipcloak-vX.Y.Z-windows-x86_64-portable.zip` holds `clipcloak.exe` and `clipcloak-ner.exe` (single-file builds) plus README/license – no `_internal` folders any more. They unpack themselves into `%TEMP%` at start (a bit slower, the NER plugin noticeably); where AppLocker/endpoint protection block `%TEMP%`, use the MSI. The MSI keeps the folder builds (fast start, nothing in `%TEMP%`).
- **Group Policy templates as a download of their own:** `clipcloak-vX.Y.Z-policies.zip` with `PolicyDefinitions\` (ADMX + `en-US`/`de-DE` ADML, ready to copy into the central store), `examples\` (`policy.yaml`, `defaults.yaml`, `policy-example.reg`) and a short guide (EN/DE). Built by the Linux job, so it is there even without a Windows runner.

## 0.1.22

- Watcher recognises **pseudonymised results** (e.g. the LLM's answer): if the copied text contains replacement values of the current project and they outweigh new findings, the popup offers *Revert* (with its shortcut) instead of Pseudonymise/Anonymise/Redact – and nothing is changed automatically, also not in the modes *by category*/*change everything* (no double pseudonymisation). New findings next to them are named ("Also found: …") and can still be pseudonymised.
  - Hints: exact replacement values of the vault with 4+ characters (names, e-mails, domains, secrets …); replacement IPs count only from two on, because they share the private ranges with real addresses.
  - Setting `watcher.offer_revert` (Settings › Watcher, on by default; also as ADMX policy).
- Workbench: a pseudonymised input is marked in the status line and *Revert* becomes the default button (Enter).

## 0.1.21

- **Fix: real IP addresses were not found** once an earlier pseudonymisation had produced a surrogate in the same /24 (e.g. `192.168.1.53` stayed unchanged after some other address had been mapped into 192.168.1.x). With "skip already pseudonymised values" IPs were skipped when they merely lay in a surrogate network – in homelabs and company networks with 192.168.x/10.x that hit real addresses. IPs are now never skipped: surrogates and real addresses share the same private ranges, and a leaked real address is worse than a second replacement.

## 0.1.20

- New detector **Long hex strings** (on, category secrets): a hex string of 32+ characters standing alone (API keys, tokens, webhook secrets such as `75d54631…c56319caa`) is found and replaced format-preserving (hex stays hex, same length, reversible). Public ids stay: image digests (`@sha256:…`, `digest:`), `commit …`, `sha256sum` output (`<hash>  file`), values after `sha256:`/`md5:`/`checksum`/`etag`, placeholders such as `0000…`.

Fewer false positives in shell commands:
- File paths are no Kubernetes references: `sh deploy/compose/start.sh`, `cat app/values.yaml`, `./deploy/x/run` no longer turn "compose" etc. into infrastructure names. `kind/name` counts only when it is not followed by `/`, is no file name and the command is no file command (sh, bash, cat, ls, cd, vi, python, git …); `deployment.apps/name` is recognised as well.
- Package names are no domains: arguments of `apt`/`apt-get`, `dnf`/`yum`, `zypper`, `apk`, `pacman`, `brew`, `snap`, `pip`, `npm`, `choco`, `winget` … install/remove (also across `\` continuations) – `containerd.io` stays. URLs (`pip install git+https://git.acme.de/…`) and anything after `&&`, `;`, `|` are still checked.
- Operating system names are no organisations: Debian, Ubuntu, Fedora, CentOS, RHEL, Rocky, Alma, Alpine, Arch, openSUSE, Proxmox, FreeBSD … also combined with GNU, Linux, Server, LTS, Enterprise, version numbers (`Debian GNU/Linux 12`, `Red Hat Enterprise Linux`); release code names (bookworm, jammy, noble …).
- More public domains are never pseudonymised: containerd.io, podman.io, etcd.io, debian.org, ubuntu.com, fedoraproject.org, kernel.org, python.org, pypi.org, npmjs.com, go.dev, crates.io …

## 0.1.19

- Images: while the plugin analyses an image (e.g. after Ctrl+Alt+I) a box over the image shows what is happening – "Analysing image …", the current step (faces 1/4, nudity 2/4, codes 3/4, text/OCR 4/4), a progress bar and the seconds so far; the button reads "Detecting …" and the status bar says so too.
- *Result → clipboard* and *Save result* are disabled until the detection is finished, so no half-redacted image can be passed on.

## 0.1.18

- Images: configurable extra margin around detected faces ("on top" of the detected box), in % of the face size (0–200, default 15):
  - in the *Image* tab (*Margin around faces*): changes the detected faces at once; boxes moved or resized by hand keep their size; the value is kept as the new default
  - in Settings › Images, also for nudity (default 12); as ADMX policies `image.face_margin` / `image.nudity_margin`.

## 0.1.17

- New optional detector **Key and certificate identifiers** (off by default, Settings › Detection; watcher category of its own, default *inform*):
  - .NET `PublicKeyToken=…` of own assemblies – the Microsoft/.NET framework tokens (`7cec85d7bea7798e`, `b77a5c561934e089`, `b03f5f7f11d50a3a`, `31bf3856ad364e35` …) identify nobody and are never reported
  - certificate thumbprints and serial numbers (`Thumbprint:`, `Serial Number:`, `fingerprint=`, `KeyId` …, also the PowerShell `Cert:\` table)
  - SSH host key fingerprints (`SHA256:…`, `MD5:aa:bb:…`), GPG fingerprints (`Key fingerprint = …`, the line below `pub`/`sec`)
  - placeholders such as `0000…` are ignored; replacements keep the format (hex stays hex, case and `:`/`-` separators stay) and are reversible.

## 0.1.16

- NER: far fewer false positives on code and logs. Entities are rejected when
  - a word is an identifier (CamelCase such as `ComInterop`, `DispatcherOperation`, `CancellationToken`, capitals + lower case such as `IDispatch`, digits such as `Int32`); name prefixes like Mc/Mac/O'/Van/Von stay allowed,
  - they are part of a dotted name or a call (`Microsoft.CSharp…`, `Avalonia.Threading…`, `Name(`),
  - the line is a stack trace / code line (`at X.Y.Z(`, `Namespace.Class.Member`, `foo()`),
  - they are well-known public companies/products (Microsoft, Google, SAP, Avalonia …).
  Measured on a .NET stack trace: 43 findings before, 0 now; names and companies in normal text are still found.
- Secrets: keys containing "public" (`PublicKeyToken=…`, `public_key:`) are no secrets. Unquoted values stop at a closing bracket they did not open (`…7798e]](System…` → `…7798e`).
- Workbench/history: findings and replacements are shown once per value with a × column (how often). Double click on a finding jumps to its next occurrence.

## 0.1.15

- Watcher: when one part is changed automatically and the rest asks, there is only **one** popup ("Already done: tracking removed: 3 · Found: ORG ×12 …") instead of a Windows notification lying over the popup.
- Notifications name removed tracking separately ("tracking removed: 3") instead of counting it as pseudonymised replacements.

## 0.1.14

- Clipboard watcher **per category**: for each category *always change*, *inform* (popup) or *nothing* – origin/tracking in links, secrets and keys, bank and card data, people and accounts, organisations and places, network, infrastructure names, custom terms. Default: tracking, secrets and bank data change at once, the rest informs. With both in one text the automatic part is done first, then the popup asks for the rest.
  - Modes: *off*, *by category* (was "critical automatically"), *inform about everything* (was "notify"), *change everything* (was "always"); the last two keep categories set to *nothing* out.
  - One action for automatic changes (`watcher.action`); `watcher.critical_types`, `watcher.critical_action` and `watcher.notify_noncritical` are replaced by `watcher.categories.<category>` (also as ADMX policies).
- Allow-listed domains are no longer reported as findings (no popups for them, not shown as findings in the workbench).

## 0.1.13

- New detector **Tracking in links** (on by default): origin marks are removed in every mode (they are not pseudonymised and not restored by revert):
  - `utm_*`, click ids (`fbclid`, `gclid`, `gbraid`, `msclkid`, `twclid`, `ttclid` …), newsletter/CRM recipient ids (`mc_eid`, `mc_cid`, `_hsenc`, `_hsmi`, `mkt_tok`, `vero_id` …), Matomo/Piwik/Webtrekk/AT Internet parameters, `_ga`/`_gl`
  - site-specific share ids: YouTube/Spotify `si`, Instagram `igsh`, X `s`/`t`, TikTok, LinkedIn, Facebook, Reddit, Google search, Amazon (incl. `/ref=…`), eBay, AliExpress
  - text fragments `#:~:text=…`
  - redirect wrappers are replaced by their target, which is then processed normally: Outlook Safe Links (the `data` part contains the recipient's e-mail address), Google `/url`, Facebook `l.php`, LinkedIn, Slack, YouTube, Steam, DuckDuckGo, Bing, Proofpoint URL Defense v2/v3
  - the URL stays valid (`?`/`&` are removed with the parameter); works in HTML links too
  - own parameters: Settings › Lists › Tracking parameters (`lists.tracking_params`, also via policy)
- Fixed: in *Redact* mode, domains on the allow list were redacted anyway.

## 0.1.12

- Fixed: Kubernetes label/annotation keys and API groups (`argocd.argoproj.io/tracking-id:`, `cert-manager.io/cluster-issuer:`, `app.kubernetes.io/name=web`) were replaced as domains, which broke the YAML. A DNS prefix followed by `/name:` or `/name=` is no longer a host. Well-known tool domains (argoproj.io, cert-manager.io, x-k8s.io, prometheus.io, coreos.com, istio.io, traefik.io, …) are always kept.
- New detector **Infrastructure names** (on by default): values of `name`, `namespace`, `instance`, `release`, `app` and similar keys, `-n/--namespace`, `deploy/<name>`-style references and ArgoCD tracking ids. Only customer-specific parts are pseudonymised; generic words and product names stay; one word gets one pseudonym everywhere (names, namespaces, tracking ids, domains, prose). New finding type `IDENTIFIER`. Extra generic words: Settings › Lists › Generic words.
- Workbench: mark any text in the input and right-click *Always replace "…"* (custom term, in the active project) or *Never replace "…"*.
- Images: **nudity** detection (exposed breasts, genitals, buttocks; NudeNet 320n, local), black by default; large images are also searched in tiles. Settings › Images and ADMX.

## 0.1.11

- **Images:** new *Image* tab to hide faces, sensitive text and codes in images.
  - Image from the clipboard or a file; `Ctrl+Alt+I` (*Redact image in clipboard*), the tray entry and the pseudonymise/anonymise/redact shortcuts open a clipboard image there. With the watcher on, a copied image shows a popup *Redact image*.
  - Automatic detection with the plugin, all local: faces (OpenCV + YuNet model, also in large images), text via OCR (RapidOCR) run through the same detectors as clipboard text (IP, e-mail, domains, secrets, custom terms, NER …) with boxes over exactly those characters, and QR codes/barcodes.
  - Effects per area: black (default for text and codes), mosaic (default for faces), blur. Areas can be drawn, moved, resized, deleted and switched by hand; the preview shows the result.
  - The result is a new, flat image without metadata, to the clipboard or as PNG/JPEG.
  - Settings › Images; ADMX policies for the image settings; action `--action redact_image`.
- The plugin now also contains OpenCV, the YuNet face model (MIT) and RapidOCR (Apache-2.0). Its self test checks OCR and QR codes too. The Linux plugin is built in the packaging job, because it is larger than GitLab's 100 MB artifact limit.
- Background jobs cancelled at exit no longer log an error.

## 0.1.10

- The main window remembers its layout: window size and position, last tab, all splitter positions and column widths (`ui.ini` next to `config.yaml`).
- History: the list gets a reasonable height by default (it was squeezed to two rows); the diff and the replacements are separated by a splitter.
- Workbench: input/findings and result/replacements can be resized with splitters.
- Column widths are only fitted to the content once; afterwards your own widths stay.
- MSI: setup wizard with license and feature selection – NER plugin, *Start with Windows* (autostart), desktop shortcut, install folder. Autostart and desktop shortcut are now features; silently still `AUTOSTART=0` / `DESKTOPSHORTCUT=1` or `ADDLOCAL`. Updates keep the chosen features. The installation can be changed later under Settings › Apps.

## 0.1.9

- Managed deployment on Windows:
  - **MSI installer** (WiX 5), per machine to `C:\Program Files\ClipCloak`, silent with `msiexec /i … /qn`. Properties `AUTOSTART` (default 1, HKLM Run for all users) and `DESKTOPSHORTCUT`, features `Main` and `NER`, major upgrade on newer versions. Suited for GPO software installation, ESET PROTECT *Software Install* and baramundi.
  - Windows builds are now folder builds (`--onedir`): nothing is unpacked to `%TEMP%` at start (AppLocker, endpoint protection). The ZIP contains `clipcloak.exe` + `_internal\`, the NER plugin in `ner\`, and the ADMX templates. The single Windows `.exe` files are no longer published.
  - Optional code signing in CI (`SIGN_PFX_BASE64`, `SIGN_PFX_PASSWORD`, `tools/sign_windows.ps1`).
- **Central settings:**
  - Defaults (changeable): `%ProgramData%\clipcloak\defaults.yaml` or `/etc/clipcloak/defaults.yaml`, registry `HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak\Recommended`.
  - Policy (enforced): `policy.yaml` in the same folder, registry `HKCU`/`HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak`.
  - **ADMX/ADML** templates (English, German) with 60 settings for Group Policy.
  - Enforced settings are greyed out in the settings, tray and workbench ("Managed by your administrator"). Policy entries in lists (custom terms, known domains, allowlists) are added to the user's entries.
  - `config.yaml` now only stores the user's own choices, so later changes to the machine defaults reach every user.
  - The Log tab shows the loaded central settings and invalid entries.
  - Examples: `policy.yaml`, `defaults.yaml`, `policy-example.reg`.
- **Projects are encrypted without a passphrase on Windows:** AES-256-GCM with a random key protected by DPAPI (bound to the Windows account). Plain project files are converted when they are opened. The project bar shows "encrypted (Windows account)", "encrypted (passphrase)" or, in red, "NOT encrypted", with an explanation in the tooltip.
- LLM: screenshot → text has its own timeout (`llm.vision_timeout`, default 180 s); the Log tab shows the timeout of each request.
- Autostart: if the installer set up autostart for all users, the user's own autostart entry is removed (no second start) and the option shows this.

## 0.1.8

- Fixed: the Linux NER plugin failed its self test (numpy: "libscipy_openblas… ELF load command address/offset not page-aligned"). `pyinstaller --strip` also stripped numpy's vendored OpenBLAS. Now only the debug symbols of the spaCy/thinc/blis extensions are removed before the build (`tools/strip_debug.py`); numpy's libraries stay untouched. Size about 82 MB.

## 0.1.7

- Releases: one download per platform.
  - Windows: `clipcloak-<version>-windows-x86_64.zip`, Linux: `clipcloak-<version>-linux-x86_64.tar.gz`.
  - Each contains the program, the NER plugin (`clipcloak-ner`), README and license; the Linux archive also a `.desktop` file and the icon, with executable bits set.
  - The archives are stored in the project's package registry, so GitLab's 100 MB limit for job artifacts does not apply to them. The program-only binaries are still linked.
- Clipboard popup: the buttons show their global shortcut (e.g. *Pseudonymise / Ctrl+Alt+P*), if one is set and registered.
- New `tools/package_release.py` builds the archives (also usable locally).
- README: installation and NER setup rewritten for the archives; duplicated NER section removed.

## 0.1.6

- Projects in the main window:
  - A bar above the tabs with the active project (drop-down), its status (saved / RAM only, number of mappings, encrypted or not) and the buttons *New project*, *Project settings* and *Delete project*.
  - A *Project* menu in the menu bar; the tray uses the same menu.
- The separate "Sprache / Language" menu is removed from the menu bar and the tray. The language is set in the settings (General).
- About: shows the project page https://github.com/it-an-der-bar/ClipCloak as a clickable link. The release link in the NER setup points to its releases.

## 0.1.5

- Activity is visible:
  - While a job runs, the status bar of the main window shows "Working: … " with a progress animation, the tray icon turns blue and the tray tooltip names the job.
  - The workbench shows its own status while working.
- New **Log** tab: shows what the program does, with times and durations:
  - actions and results (counts per type)
  - watcher decisions
  - LLM requests: purpose, host, model, duration, errors, and the items the check reported
  - NER: helper start, model loading, candidates vs. accepted entities
  - shortcuts, project switches, all notifications
- Clipboard contents never go into the log. LLM check results appear only in the Log tab (RAM), not in the log file.

## 0.1.4

- NER: far fewer false positives. Every entity from the NER plugin is now checked before it is used; this also applies to older NER helper versions, where the checks run without part-of-speech tags:
  - Spans containing code characters (`= " $ _ { } | / …`) or shell/programming keywords (`if`, `docker`, `kubectl`, `echo`, `esac` …) are rejected.
  - A person needs a first and last name made of capitalised proper nouns; the span is trimmed to that name.
  - Organisations and places must start with a capital letter. ALL-CAPS constants are rejected, and so are spans that start with an article or pronoun (for example "Deine Auswahl").
  - The NER helper now also returns part-of-speech tags. Entities without any proper noun are rejected.
  - Measured on a bash script: before, many false entities (e.g. `RUSTDESK_DETECTED="nein"`, `if has_cmd docker`, `Durchsuche`, `ACCEPT`, `Deine Auswahl`); now only `Jonas Hartmann` and `Contoso Solutions GmbH`.

## 0.1.3

- CI: The Linux NER plugin is built with `--strip` and without the spaCy tests (~120 MB → ~84 MB), so it stays below GitLab's default artifact limit of 100 MB per job.

## 0.1.2

- Fixed: after a restart (e.g. a language change) the Windows/Linux binary used the deleted temporary directory of the old process. This caused errors like "base_library.zip: No such file or directory", for example in the LLM test. The NER helper is now also started with a clean PyInstaller environment.
- Workbench laid out from left to right: 1. input (open file, from clipboard, screenshot) → 2. action buttons → 3. result (to clipboard, save, LLM check, auto-copy).
- The NER helper, when started by hand, shows what it is for and runs a self test instead of an empty console.
- Settings: closing without OK asks whether to save the changes (URL, token …). `config.yaml` keeps the previous version as `config.yaml.bak`. An unreadable configuration is set aside with a time stamp and reported at start instead of being silently replaced.

## 0.1.1

- Pseudonyms are persisted by default in the project "Standard", so reverting works after a restart. "RAM only" has to be chosen explicitly and is labelled "lost on exit".
- Whole files: *Process file …* in the tray and the File menu (background processing, keeps encoding and line endings, result saved next to the source as `*.pseudo.*`, `*.anon.*` …). The workbench can load and save files.
- About 15× faster on large texts (overlap resolution in O(n log n)); 1 MB takes about a second.
- Workbench: one button each for pseudonymise, anonymise, redact and revert (replaces the mode drop-down). The result is copied to the clipboard automatically; this can be switched off in the workbench or in the settings (`general.workbench_auto_copy`).
- Language: a bilingual "Sprache / Language" menu in the tray and the main window. After a change the application offers to restart itself (also available as `--action restart`).
- The `Authorization: Bearer` scheme word is no longer treated as a secret.
- Settings › NER plugin: setup steps with the exact file names, the target folder, status (found / not found) and buttons to open the release page and the program folder.
- Settings › LLM reworked into three steps: connection (URL, optional token) → *Test connection & load models* (adds `/v1` if missing) → model drop-downs → features.
- The NER helper is found next to the program even with its release file name, is started in the background at launch, and acronyms such as VPN or DNS are no longer reported as organisations.

## 0.1.0

First version:

- Tray application for Windows and Linux (X11, Wayland best effort) with global shortcuts (Win32 and X11), and `--action` commands for Wayland.
- Modes: redact, anonymise (realistic values or placeholders) and pseudonymise, including revert.
- Class- and prefix-preserving IP mapping, format-preserving surrogates, and consistent word mapping across domains, e-mail addresses, NetBIOS domains and organisations.
- Detectors for network data, identities, secrets, custom terms, known domains and names learned from e-mail addresses.
- Clipboard watcher (off, notify, critical automatically, always) with an action popup.
- Workbench, history with diff view, mapping overview with CSV export.
- Projects with optional AES-256-GCM encryption, plus project-specific terms and domains.
- HTML clipboard processing.
- Optional NER plugin (spaCy helper binary) and LLM features (screenshot → text, result check, detector).
- Headless CLI (`process`, `revert`, `analyze`, `projects`).
- GitLab CI: tests on push; Linux/Windows binaries and NER plugin on tags.
