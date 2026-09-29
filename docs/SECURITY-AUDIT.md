# Security review – ClipCloak 0.1.27

Date: 2026-09-29 · Scope: the whole repository at version 0.1.27 (program, NER/vision helper,
packaging, CI) · Reporting vulnerabilities: see [SECURITY.md](../SECURITY.md)

## Method

- Manual review of every place where data can leave the machine or is written to disk, plus a
  second, independent review of the same questions and of the fixes.
- Static analysis with `ruff` (pyflakes, pycodestyle, bugbear, pyupgrade and the bandit `S` rules);
  clean, and part of both CI pipelines.
- Every fix has a regression test (`tests/`); the Linux keyring encryption was also tested against
  a real GNOME Keyring (Secret Service) instance.
- Repository hygiene: no personal or company data, no internal host names, no token-shaped strings
  in sources, tests or history.

## Data flows

| Path | When | What leaves the machine |
|---|---|---|
| LLM client (`clipcloak/llm/client.py`) | only when an endpoint is configured **and** an LLM feature is used | *LLM check*: the processed text (never the input); *screenshot → text*: the image; *LLM detector*: the original text of an explicit action – never from the clipboard watcher |
| "Test connection" (settings) | on click | `GET /models` with the configured API key |
| Links in the UI (releases, about) | on click | opens the browser |
| NER / vision helper | local subprocess, JSON over stdin/stdout | nothing – models are bundled, no downloads at run time |
| Everything else | – | nothing: no telemetry, no update check, no crash reporting |

CI only: `tools/package_release.py` uploads build artefacts to the GitLab package registry;
GitHub Actions uploads them as release assets.

## Findings and status

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Any local user could place `policy.yaml`/`defaults.yaml` in `%ProgramData%\clipcloak` (writable by users by default) and enforce settings for everyone on the machine, e.g. an LLM endpoint of his own. | **Fixed** – files are only read when the file *and* its folder can only be changed by SYSTEM, TrustedInstaller, Administrators or a member of it (Linux: root, not writable by group/others); the MSI creates the folder with an ACL that only lets administrators write. |
| 2 | High | Linux: project files (mappings incl. original values and secrets, history) were plain JSON when no passphrase was set. | **Fixed** – AES-256-GCM with a key kept in the desktop keyring (Secret Service); retried if the keyring starts later; without any keyring the UI keeps saying "NOT encrypted". |
| 3 | Medium | Workbench "LLM check" sent the unprocessed input when nothing had been processed yet. | **Fixed** – only the result is sent. |
| 4 | Medium | With the LLM detector enabled, every clipboard change went to the endpoint (clipboard watcher). | **Fixed** – the watcher never runs the LLM detector; only explicit actions do. |
| 5 | Medium | LLM error responses (often echoing the request text) were written to the log file and history. | **Fixed** – only status code and reason are logged; the body is shown in the in-memory Log tab only. |
| 6 | Medium | HTML clipboard: comments (Office metadata such as the author), scripts and most attribute values passed through unchanged. | **Fixed** – comments, CDATA, processing instructions and scripts are dropped (CSS comments inside `<style>` are kept); all attribute values are processed except pure formatting and embedded `data:` images. |
| 7 | Medium | *Keep original text in history = off* did not cover revert results, LLM-check warnings, or entries loaded from a project. | **Fixed** – all are masked; switching the option off masks existing entries and saves the project at once. |
| 8 | Medium | The NER helper was also searched by wildcard name next to the program and in PATH (incl. the current directory on Windows). | **Fixed** – fixed paths only; a configured path must be absolute. |
| 9 | Medium | Linux: files were created with the default umask and chmod-ed afterwards (short readable window); data folder and log file were world-readable. | **Fixed** – files created with mode 0600 from the start (`umask 077`), folders 0700. |
| 10 | Low | urllib followed redirects (the API key could go to another host), used environment proxies also for local endpoints, accepted non-http schemes. | **Fixed** – redirects refused, http/https only, no proxy for loopback, warning for an API key over plain http to a remote host. |
| 11 | Low | LLM API key stored in plain text in `config.yaml`. | **Fixed** – sealed with DPAPI / the keyring where available; no backup copy with a plain key. |
| 12 | Low | A successful connection test switched LLM features on. | **Fixed** – it no longer does. |
| 13 | Low | A broken `config.yaml` could put a line of it (API key, custom term) into the log. | **Fixed** – only error type and position are logged. |
| 14 | Low | scrypt N = 2^15 for passphrase projects. | **Fixed** – N = 2^17 (OWASP); existing files keep their stored parameters. |
| 15 | Low | Restored originals (revert) could end up in the Windows clipboard history / cloud clipboard or in clipboard managers. | **Fixed** on Windows and KDE (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0`, `x-kde-passwordManagerHint`). **Open** for the Wayland `wl-clipboard` backend. |
| 16 | Low | Single-instance IPC name predictable (another account could occupy it → denial of service). | **Fixed** on Linux (socket in `$XDG_RUNTIME_DIR`). **Open** on Windows (named pipe; denial of service only, access is limited to the same user). |
| 17 | Info | Code signing passed the certificate password on the command line. | **Fixed** – the certificate is imported into the user store and used by thumbprint; on GitHub the secrets are only visible to the signing steps. |

## Accepted / open

- Dependencies (`requirements*.txt`) are version ranges without hashes; CI actions are pinned by
  major version, not by commit hash.
- Pseudonymisation is keyed (HMAC with a random 32-byte vault key); IP mapping is prefix-preserving
  by design and therefore keeps the subnet structure visible. Anonymisation is deterministic within
  one session.
- The project *name* is readable in the project file. Policy-provided LLM tokens are readable by
  the users (registry / policy file).
- Detection is heuristic – always check the result before sharing sensitive material.

## Verification

`ruff check .` – clean · `python -m unittest discover -s tests` – all tests pass (Linux; the
Windows-only tests for DPAPI, registry policies and the permission check run in both CI systems).
