# Contributing

Thanks for contributing to Fariid Tech Security AI.

## Getting started

```bash
git clone https://github.com/FariidTech/fariid-security-ai.git
cd fariid-security-ai
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Development workflow

1. Open an issue describing the change (bug, feature, or tool wrapper).
2. Create a branch and make your change.
3. Add tests for new behavior (unit tests + CLI tests; mocked AI/tools).
4. Run the checks locally:

   ```bash
   make lint
   make typecheck
   make test
   ```

5. Open a pull request.

## Code style

- Python 3.10+, type hints everywhere, `from __future__ import annotations`.
- `ruff` (lint + format) and `mypy` must be clean.
- Match the surrounding code's naming and comment density.

## Adding a new tool wrapper

1. Add an entry to `fariid_sec/tools/catalog.py` (binary, category, risk,
   description, install hint).
2. If it should be callable by the AI agent, add a structured tool to
   `fariid_sec/tools/actions.py` with a JSON schema and a handler that builds a
   safe argument vector (never `shell=True`).
3. Add a parser under `fariid_sec/parsers/` if it emits structured findings.
4. Add tests.

## Adding a new AI provider

Subclass `fariid_sec.ai.base.AIProvider` and register it in
`fariid_sec.ai.factory`. Providers must implement `chat`, `chat_stream`, and
`check_health`, and raise the typed exceptions in `base`.

## Safety rules (non-negotiable)

- Never add a generic "run any shell command" tool.
- Never send secrets to an AI provider; always redact.
- Keep destructive actions behind explicit authorization gates.
- Preserve the rule that `--yes` only applies to authorized targets.

## License

By contributing, you agree your contributions are licensed under the MIT License.
