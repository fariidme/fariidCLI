# Security Policy

## Intended use

Fariid Tech Security AI is a tool for **authorized** security testing,
penetration testing, CTFs, vulnerability assessment, and defensive security. You
must only test systems you own or have explicit, written authorization to test.

Unauthorized scanning, exploitation, or data access is illegal and not
supported.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Email: `security@fariid.tech` (placeholder — update for your org)
- Do not include live credentials or customer data.

We aim to acknowledge within 48 hours and provide an initial assessment within
5 business days.

## What the CLI does to protect secrets

- **Secret redaction** — before any tool output, project file, or configuration
  value is sent to an AI provider, it passes through `fariid_sec.security.redact`,
  which masks common secret shapes (`sk-*` keys, `Authorization: Bearer …`,
  passwords, AWS keys, private-key blocks, JWTs, GitHub tokens, …).
- **Never auto-uploads** — the CLI never uploads the filesystem. It only sends
  the specific text the operator asked it to analyze.
- **Path guardrails** — the `read_file` agent tool refuses sensitive paths
  (`/etc/shadow`, `~/.ssh`, `.env`, cloud-credential dirs, …).
- **No secrets in history** — chat sessions store only conversation text; API
  keys are never written into session files.
- **Masked display** — configuration output masks API keys.
- **Restricted file permissions** — config, targets, and sessions are written
  with `0600` permissions.

## What the CLI does to enforce authorization

- **Authorized target list** — active scans prompt for confirmation. The `--yes`
  flag only applies to targets explicitly stored in the authorized target list
  (or loopback/private lab addresses).
- **Execution modes** — `passive` (DNS/WHOIS/headers/certs), `active` (port and
  vulnerability scanning), `lab` (CTF/local VMs).
- **Structured tools only** — the agent cannot emit arbitrary shell commands; it
  selects from a fixed, typed tool set, each with a risk level and an
  authorization requirement.
- **Confirmation gates** — high/critical-risk tools (sqlmap, exploitation,
  password auditing) require explicit operator confirmation before execution.
- **No destructive-by-default** — the agent never launches destructive
  exploitation against arbitrary targets.

## Responsible disclosure expectations

If you use this tool to find a vulnerability in a third-party system, disclose
it to the system owner responsibly and follow applicable laws and disclosure
norms.
