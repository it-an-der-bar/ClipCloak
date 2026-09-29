# Security

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub: *Security › Report a vulnerability* in this
repository (private security advisory). Do not open a public issue for security problems.

Please include the version, the operating system and the steps to reproduce. Never attach real
clipboard contents, mapping files or project files – use made-up data.

## Scope and design

- ClipCloak processes clipboard contents locally. It has no telemetry and no update check; it only
  connects to an LLM endpoint that you configure and use.
- Mappings (original ↔ replacement) are kept in RAM or in project files encrypted with AES-256-GCM
  (key from the Windows account via DPAPI, the Linux desktop keyring, or a project passphrase).
- Detection is heuristic: always check the result before you share sensitive material.

See the *Security notes* section of the README for details and
[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) for the last security review (findings and their status).
