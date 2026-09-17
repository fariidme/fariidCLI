# Fariid Tech Security AI

> An AI-powered security command center for Kali Linux.

**Fariid Tech Security AI** is a production-oriented, open-source CLI that
orchestrates legitimate security-testing tools installed on Kali Linux through a
clean, safe, and extensible Python architecture — with the **DeepSeek API** as a
first-class AI provider.

```text
╭───────────────────────────────────────╮
│     FARIID TECH SECURITY AI           │
│     AI-Powered Kali Security CLI      │
╰───────────────────────────────────────╯

Provider : deepseek
Model    : deepseek-chat
Platform : Kali Linux
Mode     : passive
```

> ⚠️ **Authorization required.** Only test systems you own or have explicit,
> written authorization to test. Unauthorized scanning of systems you do not own
> is illegal and against the purpose of this tool.

---

## Highlights

- **Real AI agent** — a tool-calling loop that understands a request, selects
  appropriate Kali tools, executes them through a controlled subprocess layer,
  parses output, analyzes findings, and reports severity/evidence/remediation.
- **DeepSeek first-class** — streaming, tool/function calling, JSON output,
  conversation history, reasoning mode (`deepseek-reasoner`), token usage,
  retries, timeouts, rate-limit and invalid-key handling.
- **Multi-provider** — `deepseek`, `ollama` (local models: `llama3`, `qwen`,
  `deepseek-coder`), and any OpenAI-compatible endpoint.
- **Safe by design** — structured tools (no arbitrary shell), target
  authorization, execution modes (`passive` / `active` / `lab`), secret
  detection/redaction before any data reaches an AI provider.
- **Automatic tool discovery** — detects which Kali binaries are installed and
  reports missing tools with install hints (never auto-installs).
- **Professional reporting** — HTML, JSON, Markdown, TXT, and (optional) PDF.
- **Beautiful terminal UX** — colors, tables, panels, spinners, streaming.

---

## Installation

### One-command installer

```bash
git clone https://github.com/FariidTech/fariid-security-ai.git
cd fariid-security-ai
./install.sh
```

The installer checks your OS and Python, creates a virtual environment, installs
the CLI, writes `.env.example`, runs `fariid-sec doctor`, and prints next steps.
It never downloads unknown remote scripts or silently installs system packages.

### Manual install (Kali Linux)

```bash
git clone https://github.com/FariidTech/fariid-security-ai.git
cd fariid-security-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify:

```bash
fariid-sec doctor
fariid-sec version
```

---

## DeepSeek setup

```bash
export DEEPSEEK_API_KEY="sk-..."
fariid-sec config set provider deepseek
fariid-sec config set model deepseek-chat      # or deepseek-reasoner
```

You can also store the key interactively (prompt hides input):

```bash
fariid-sec config set api-key
```

Supported environment variables:

```text
DEEPSEEK_API_KEY
DEEPSEEK_BASE_URL   (default https://api.deepseek.com)
DEEPSEEK_MODEL
```

The DeepSeek integration supports streaming, tool/function calling, structured
JSON output, conversation history, system prompts, reasoning content, token
usage reporting, and typed error handling for timeouts, rate limits (429),
invalid keys (401), and retries.

---

## Ollama setup (local models)

```bash
ollama pull llama3
fariid-sec config set provider ollama
fariid-sec config set model llama3
```

```bash
fariid-sec --provider ollama chat
```

Works with any locally pulled model, e.g. `qwen2.5-coder`, `deepseek-coder`,
`llama3`.

---

## Commands

```text
fariid-sec                        show banner + help
fariid-sec chat                   interactive streaming chat (with sessions)
fariid-sec agent                  AI security agent (tool-calling loop)
fariid-sec ask "…"                natural-language → structured plan
fariid-sec scan <target>          active scan (nmap + optional nuclei)
fariid-sec recon <target>         passive recon (whois/DNS/HTTP headers)
fariid-sec web-audit <url>        web app audit
fariid-sec network <cidr>         network/host discovery
fariid-sec dns <domain>           DNS enumeration
fariid-sec ssl <host>             TLS/certificate inspection
fariid-sec vuln <target>          vulnerability scanning
fariid-sec analyze <file>         AI analysis of tool output/results
fariid-sec explain "nmap result"  explain tool output or a concept
fariid-sec report --input results.json --format html
fariid-sec tools                  list installed/missing tools
fariid-sec target add|list|remove|show
fariid-sec config set|get|show
fariid-sec session list|new|resume|delete
fariid-sec mode passive|active|lab
fariid-sec doctor                 environment self-check
fariid-sec update                 update the CLI
fariid-sec version
```

Global flags: `--provider`, `--model`, `--mode`, `--yes`, `--json`, `--verbose`.

---

## Examples

```bash
# Configure DeepSeek
fariid-sec config set provider deepseek
fariid-sec config set api-key

# Authorize a lab target
fariid-sec target add mylab 192.168.1.10
fariid-sec target add staging https://staging.example.com
fariid-sec target list

# Scan an authorized target
fariid-sec scan 192.168.1.10
fariid-sec scan 192.168.1.10 --nuclei

# Passive recon
fariid-sec recon example.com

# Web audit
fariid-sec web-audit https://example.com

# Ask the agent in natural language
fariid-sec ask "enumerate the services running on my lab machine" --target 192.168.1.10

# Interactive agent
fariid-sec agent
> I need to audit my web server at 10.0.0.5

# Chat with persistent sessions
fariid-sec chat
fariid-sec session list
fariid-sec session resume <id>

# Generate a report
fariid-sec report --input results.json --format html
```

### CTF / lab examples

```bash
fariid-sec mode lab
fariid-sec target add juice-shop http://127.0.0.1:3000
fariid-sec web-audit http://127.0.0.1:3000
fariid-sec agent --target http://127.0.0.1:3000
```

---

## Architecture

```
AIProvider (abstract)
 ├── DeepSeekProvider        (OpenAI-compatible + reasoning_content)
 ├── OllamaProvider          (native /api/chat)
 └── OpenAICompatibleProvider

SecurityAgent                 # tool-calling loop: request → tools → parse → report
 ├── Planner                  # NL → structured JSON plan
 └── prompts

tools/
 ├── catalog / registry       # auto-discovery of Kali binaries
 └── actions                  # structured AI tools (run_nmap, run_nuclei, …)

runners/                      # CommandRunner (subprocess, no shell) + ResultNormalizer
parsers/                      # nmap / nuclei / generic output parsers
targets/                      # authorized target profiles
reports/                      # HTML/JSON/MD/TXT/PDF generator
security/                     # secret redaction + target/scope validation
sessions/                     # persistent chat history (no API keys stored)
config/                       # YAML config + env-var overrides
```

The AI never generates arbitrary shell commands. It selects from a fixed set of
typed tools (`run_nmap`, `run_nuclei`, `run_ffuf`, `run_gobuster`, `run_nikto`,
`run_sqlmap`, `run_searchsploit`, `run_dns_enum`, `run_http_probe`,
`read_file`). Every tool has a name, description, JSON-schema arguments, risk
level, authorization requirement, timeout, and output parser.

---

## Supported tools

| Category | Tools |
| --- | --- |
| Information gathering | nmap, masscan, amass, subfinder, theHarvester, whois |
| Web security | nikto, gobuster, ffuf, feroxbuster, whatweb, httpx, curl, sqlmap |
| Vulnerability | nmap NSE, nikto, nuclei, searchsploit |
| Network | nmap, tcpdump, tshark, netcat |
| DNS | dig, host, dnsenum, dnsrecon |
| TLS/SSL | openssl, sslscan, testssl.sh |
| Wireless | aircrack-ng, airmon-ng, airodump-ng |
| Password auditing | john, hashcat, hydra |
| Exploitation / lab | msfconsole, msfvenom |

Tools are discovered at runtime — the CLI never assumes a tool is installed and
reports the appropriate `sudo apt install …` hint when one is missing.

---

## Configuration

Configuration lives in `~/.config/fariid-sec/config.yaml` (override with
`$FARIID_SEC_HOME`). Secrets are stored with `0600` permissions and never
printed in full.

```bash
fariid-sec config set provider deepseek
fariid-sec config set model deepseek-chat
fariid-sec config set mode active
fariid-sec config set api-key          # prompts for the key (hidden)
```

---

## Security policy

See [SECURITY.md](SECURITY.md). In brief: secrets are redacted before any data is
sent to an AI provider; `.env`, SSH keys, browser data, and cloud credentials are
never transmitted; active/destructive actions require explicit authorization and
an authorized target.

---

## Development

```bash
pip install -e ".[dev]"

make lint       # ruff
make typecheck  # mypy
make test       # pytest
make test-cov   # pytest --cov
```

CI runs lint, type-check, and tests on Python 3.10 / 3.11 / 3.12 via GitHub
Actions.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests are welcome.

## License

MIT — see [LICENSE](LICENSE).

---

*Fariid Tech Security AI — an AI-powered security command center for Kali Linux.*
