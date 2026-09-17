# Usage

## Quick start

```bash
# 1. Install
git clone https://github.com/FariidTech/fariid-security-ai.git
cd fariid-security-ai && ./install.sh

# 2. Configure DeepSeek
export DEEPSEEK_API_KEY="sk-..."
fariid-sec config set provider deepseek

# 3. Verify
fariid-sec doctor
```

## Modes

| Mode | Allows |
| --- | --- |
| `passive` | DNS, WHOIS, HTTP headers, certificate inspection, public metadata |
| `active` | port scanning, service enumeration, vulnerability scanning, authorized web testing |
| `lab` | everything — Hack The Box, TryHackMe, CTFs, DVWA, Metasploitable, Juice Shop |

```bash
fariid-sec mode
fariid-sec mode lab
```

## Authorizing targets

```bash
fariid-sec target add mylab 192.168.1.10
fariid-sec target add staging https://staging.example.com
fariid-sec target list
fariid-sec target show mylab
fariid-sec target remove mylab
```

Active scans show an authorization panel before running:

```text
Target: 192.168.1.10
Mode:   AUTHORIZED SECURITY TEST
Tools:  nmap, nuclei
Continue? [y/N]
```

`--yes` skips the prompt only when the target is in the authorized list.

## Scans and recon

```bash
fariid-sec scan example.com
fariid-sec scan 192.168.1.10 --ports 1-1000 --nuclei
fariid-sec recon example.com
fariid-sec web-audit https://example.com
fariid-sec network 192.168.1.0/24
fariid-sec dns example.com
fariid-sec ssl example.com
fariid-sec vuln example.com
```

## The AI agent

```bash
fariid-sec agent
> I need to audit my web server at 10.0.0.5
```

```bash
fariid-sec agent "enumerate services on my lab machine" --target 192.168.1.10
```

## Natural-language planning

```bash
fariid-sec ask "audit this web application" --target https://example.com
```

This prints a structured plan (target, objective, tools, actions, risk) and
optionally executes it.

## Chat with sessions

```bash
fariid-sec chat
fariid-sec chat --message "explain SQL injection"
fariid-sec session list
fariid-sec session resume <id>
fariid-sec session delete <id>
```

## Analysis and explanation

```bash
fariid-sec explain "nmap -sV output ..."
fariid-sec analyze results.json
```

## Reporting

```bash
fariid-sec report --input results.json --format html
fariid-sec report --input results.json --format md --output out/report.md
```

Supported formats: `html`, `json`, `md`, `txt`, `pdf` (PDF requires the `pdf`
extra: `pip install -e ".[pdf]"`).

## Configuration

```bash
fariid-sec config show
fariid-sec config get provider
fariid-sec config set provider deepseek
fariid-sec config set model deepseek-chat
fariid-sec config set api-key        # interactive, hidden input
```

## Environment variables

```text
DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
OLLAMA_BASE_URL
OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
FARIID_SEC_MODE, FARIID_SEC_HOME
```
