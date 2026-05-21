# CLI Assistant

> This project contains AI-generated code.

CLI Assistant is a local-first terminal agent for homelab and host administration. It accepts natural language, plans small diagnostic steps with a configured model, runs approved commands, records compact local observations, and summarizes what it found.

It is intentionally minimal: no browser automation, no SSH by default, no broad autonomous workflows. It focuses on local shell diagnostics, network checks, Docker/container inspection, optional approved web search, and explicit approval before risky actions.

## Requirements

- Python 3.12+ for the recommended source install.
- A local or remote OpenAI-compatible model endpoint, such as LM Studio or Ollama.
- Optional: Docker and Docker Compose for containerized use.
- Optional: SearXNG or Brave Search for approved web search.

## Install From Source

Running from source is the recommended path when you want the assistant to inspect the actual host environment.

```bash
cp .env.example .env
pip install -r requirements.txt
python -m src.main
```

The CLI starts in `ask` mode by default. You can choose a mode explicitly:

```bash
python -m src.main --mode safe   # read-only local diagnostics only
python -m src.main --mode ask    # read-only diagnostics auto-run; risky commands prompt
python -m src.main --mode power  # direct admin/remote/search commands run without prompting
```

Common `.env` settings:

```env
CA_LLM_PROVIDER=openai-compatible
CA_LLM_MODEL=local-model-name
OPENAI_COMPATIBLE_BASE_URL=http://127.0.0.1:1234/v1
OPENAI_COMPATIBLE_API_KEY=local
CA_RUNTIME_CONTEXT_DIR=runtime-context
```

Secrets belong in `.env` or the host environment. Do not hard-code keys in source files.

## Docker Compose

Docker Compose is useful when you want a repeatable packaged runtime, especially for Docker/container checks. It is not identical to running from source on the host.

```bash
cp .env.example .env
docker compose build
docker compose run --rm cli-assistant
```

Current compose expectations:

- Works best on Linux. `network_mode: host` lets Linux containers reach host services on `127.0.0.1`, such as LM Studio or local SearXNG.
- Docker Desktop on macOS/Windows may need a different model URL, commonly `http://host.docker.internal:<port>/v1`.
- `./runtime-context` is mounted into the container so findings, memory, audit logs, notes, incidents, and inventory persist.
- `/var/log` is mounted read-only for host log inspection where available.
- `/var/run/docker.sock` is mounted so the assistant can inspect local containers. Treat this as highly privileged because Docker socket access is not meaningfully read-only.
- Host service commands such as `systemctl status nginx` may describe the container environment, not the host, unless the needed host paths/services are deliberately exposed.

If Docker behavior is confusing, first confirm the model endpoint from inside the container:

```bash
docker compose run --rm --entrypoint sh cli-assistant
```

Then test the endpoint with the tools available in the image or adjust `OPENAI_COMPATIBLE_BASE_URL` in `.env`.

## Optional Providers

Web search is off by policy until approved in the CLI. SearXNG is the default search provider:

```env
CA_SEARCH_PROVIDER=searxng
CA_SEARXNG_URL=http://127.0.0.1:8080/search
```

For Brave Search:

```env
CA_SEARCH_PROVIDER=brave
BRAVE_SEARCH_API_KEY=YOUR_API_KEY_HERE
```

## Usage Examples

```text
ping 192.168.1.1
troubleshoot github
scan ports on 192.168.1.10
discover hosts on 192.168.1.0/24
what network is this machine on?
check docker containers
parse through logs for errors
bash docker ps
bash systemctl status nginx
search online for the current traefik docker compose labels
```

## Safety Model

- Clearly read-only diagnostics can run without prompting when they pass the shell policy.
- Risky commands require approval, including `sudo`, SSH/SCP, package managers, Docker mutations, service changes, file writes, shell chains, redirection, inline scripts, and `web_search`.
- Approved interactive shell commands run behind a pseudo-terminal so child terminal state changes do not leak into the assistant prompt.
- In `safe` mode, risky shell commands are denied instead of prompting.
- In `power` mode, risky shell commands and web search run without prompting. Use it only when you want YOLO-style local execution.
- Vulnerability and port scans are limited to private/local targets unless the user explicitly confirms an external/public target.
- Search results are used only inside the current agent run.
- Audit events are written under `runtime-context/audit`.

## Runtime Context

At startup the assistant creates this data-only structure under `CA_RUNTIME_CONTEXT_DIR`:

```text
runtime-context/
├── audit/              # JSONL audit events
├── findings/           # Daily command observations
├── incidents/          # Human-maintained incident notes
├── inventory/          # Bounded host and network profiles
├── memory/             # Recent chat memory
├── notes/              # Human-maintained notes
└── skills/             # Human-maintained procedures/playbooks
```

These files are plain Markdown or JSONL. Findings and notes directories are data-only and should not be executable.

## Development

```bash
pip install -r requirements-dev.txt
pytest -p no:cacheprovider
```

When adding a new tool, keep it small: return a structured `dict`, export it from `src/core_functions.py` if the agent should call it, add planning guidance only when needed, decide whether it updates findings/inventory, and add focused tests.

## Project Layout

```text
src/
├── agent.py             # Interactive agent facade
├── agent_executor.py    # Executes planned steps and reviews observations
├── agent_planner.py     # Deterministic and model-assisted planning
├── bash_tool.py         # Policy-checked shell execution
├── findings.py          # Findings writer and result summaries
├── knowledgebase.py     # Runtime context and inventory updates
├── llm_providers.py     # OpenAI-compatible and Gemini adapters
├── policy.py            # Editable command approval policy
├── pty_runner.py        # PTY boundary for approved interactive commands
├── search.py            # SearXNG and Brave Search providers
└── network/             # Ping, traceroute, DNS, discovery, scans
```

Tests live in `tests/`.

## License

MIT. See `LICENSE`.
