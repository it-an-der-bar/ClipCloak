# Changelog

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
