# Changelog

## 0.1.1

- Workbench: one button each for pseudonymise, anonymise, redact and revert (replaces the mode drop-down). The result is copied to the clipboard automatically; this can be switched off in the workbench or in the settings (`general.workbench_auto_copy`).
- Language: a bilingual "Sprache / Language" menu in the tray and the main window. After a change the application offers to restart itself (also available as `--action restart`).
- The `Authorization: Bearer` scheme word is no longer treated as a secret.
- Settings › NER plugin: setup steps with the exact file names, the target folder, status (found / not found) and buttons to open the release page and the program folder.
- Settings › LLM reworked into three steps: connection (URL, optional token) → *Test connection & load models* (adds `/v1` if missing) → model drop-downs → features.
- Settings › NER plugin: setup steps with the exact file names, the target folder, status (found / not found) and buttons to open the release page and the program folder.
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
