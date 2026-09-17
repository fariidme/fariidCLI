# Architecture

## Overview

```
                    ┌────────────────────────────────────┐
                    │  fariid-sec (click CLI)            │
                    │  chat / agent / ask / scan / …     │
                    └───────────────┬────────────────────┘
                                    │
            ┌───────────────────────┼────────────────────────┐
            │                       │                        │
   ┌────────▼────────┐     ┌────────▼────────┐     ┌─────────▼─────────┐
   │  agent/          │     │  tools/          │     │  runners/         │
   │  SecurityAgent   │────▶│  actions (typed  │────▶│  CommandRunner    │
   │  Planner         │     │  tool handlers)  │     │  (subprocess)     │
   └────────┬─────────┘     └────────┬─────────┘     └─────────┬─────────┘
            │                        │                        │
            │                  ┌─────▼──────┐                 │
            │                  │ registry/  │                 │
            │                  │ catalog    │                 │
            │                  └────────────┘                 │
   ┌────────▼─────────┐                              ┌────────▼─────────┐
   │  ai/              │                              │  parsers/        │
   │  DeepSeek / Ollama│                              │  nmap / nuclei   │
   │  / OpenAI-compat  │                              └────────┬─────────┘
   └───────────────────┘                                       │
            │                                          ┌───────▼────────┐
            │                                          │  security/     │
            │                                          │  redact        │
            │                                          └────────────────┘
            │
   ┌────────▼─────────┐     ┌───────────────┐     ┌────────────────┐
   │  targets/         │     │  reports/      │     │  sessions/      │
   │  authorization   │     │  HTML/JSON/…   │     │  chat history   │
   └───────────────────┘     └───────────────┘     └────────────────┘
```

## The agent loop

`fariid_sec.agent.SecurityAgent.run()` implements a real tool-calling loop:

1. Build a system prompt from the execution mode, target, and platform.
2. Redact the user request.
3. Call the provider with the set of structured tool definitions allowed for the
   current mode.
4. If the model returns tool calls, gate each by risk/authorization, execute the
   handler (which builds a safe argv and runs it via `CommandRunner`), and append
   the result as a `tool` message.
5. Repeat until the model returns a final answer, then surface findings and token
   usage.

The agent never constructs arbitrary shell commands; it can only invoke the
typed tools in `fariid_sec.tools.actions`.

## Providers

- `AIProvider` (abstract) defines `chat`, `chat_stream`, and `check_health`.
- `OpenAICompatibleProvider` implements the Chat Completions protocol (streaming,
  tool calls, JSON mode, usage, typed errors, retries).
- `DeepSeekProvider` subclasses it and additionally captures `reasoning_content`
  for reasoning models.
- `OllamaProvider` speaks Ollama's native `/api/chat` (ndjson streaming, tools,
  `/api/tags` health check).
- `factory.create_provider()` resolves config + environment variables.

## Command execution

All external tools run through `fariid_sec.runners.CommandRunner`, which:

- never uses `shell=True`,
- passes an argument vector,
- enforces a timeout,
- captures stdout/stderr as text,
- raises `CommandNotFound` for missing binaries.

`ResultNormalizer` strips ANSI, truncates, and redacts secrets before output is
shown or sent to an AI provider.

## Authorization model

- `TargetManager` stores explicitly authorized targets.
- Active scans call `_authorize`, which validates the target and prompts for
  confirmation; `--yes` is honored only for stored authorized targets (or
  loopback/private lab addresses).
- The agent's structured tools carry `risk` and `requires_auth`; high/critical
  tools require operator confirmation.

## Data flow for a scan

```
scan 8.8.8.8
 └─ _authorize (validate + confirm + authorized-list check)
    └─ _run_nmap → CommandRunner(["nmap","-oG","-",...])
       └─ ResultNormalizer → redact/truncate
          └─ OutputParser.parse("nmap") → open ports
             └─ _findings_from_nmap → Finding[]
                └─ ReportData → JSON (saved) → report command → HTML/MD/PDF
```
