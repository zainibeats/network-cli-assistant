# Network CLI Assistant

> This project contains AI-generated code.

Network CLI Assistant is a local-first terminal agent for homelab and host administration. It accepts natural language, asks a configured model to plan small tool steps, runs approved diagnostics, records compact local observations, and summarizes what it found.

The assistant is intentionally minimal. It does not use browser automation, SSH by default, or broad autonomous workflows. It focuses on local shell diagnostics, network checks, Docker/container inspection, optional approved web search, and explicit approval before risky actions.

## Features

- Local-first agent loop with OpenAI-compatible endpoints by default, plus optional Gemini support.
- Deterministic and model-assisted planning for network, service, Docker, logs, disk, memory, and process diagnostics.
- Safe-mode shell policy: clearly read-only commands can run automatically; risky or mutating commands require terminal approval.
- Optional web search through SearXNG or Brave Search, treated as a risky action that can be approved once or for the session.
- Runtime context in plain Markdown/JSONL for findings, inventory, audit logs, recent memory, notes, incidents, and skills.
- Docker-first runtime with host networking, optional host log access, and Docker socket access for container workflows.

## Requirements

- Docker and Docker Compose for the recommended runtime.
- Python 3.12+ for running directly from source. The Dockerfile uses Python 3.13.
- A local or remote OpenAI-compatible model endpoint, such as LM Studio or Ollama.
- Optional: a local SearXNG instance at `http://127.0.0.1:8080/search`.
- Optional: a Brave Search API key.

## Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Common settings:

```env
NCA_LLM_PROVIDER=openai-compatible
NCA_LLM_MODEL=local-model-name
OPENAI_COMPATIBLE_BASE_URL=http://127.0.0.1:1234/v1
OPENAI_COMPATIBLE_API_KEY=local
NCA_RUNTIME_CONTEXT_DIR=runtime-context
```

Optional web search:

```env
NCA_SEARCH_PROVIDER=searxng
NCA_SEARXNG_URL=http://127.0.0.1:8080/search
```

For Brave Search:

```env
NCA_SEARCH_PROVIDER=brave
BRAVE_SEARCH_API_KEY=YOUR_API_KEY_HERE
```

Secrets belong in `.env` or the host environment. Do not hard-code keys in source files.

## Running

Docker is the recommended path:

```bash
docker compose build
docker compose run --rm network-cli-assistant
```

Run from source when you want direct host visibility:

```bash
pip install -r requirements.txt
python -m src.main
```

The Docker Compose service uses host networking so the default LM Studio/SearXNG URLs on `127.0.0.1` can work from the container on Linux. The compose file also mounts `./runtime-context` for assistant-owned notes and `/var/log` read-only for log inspection. It mounts the Docker socket for container inspection and approved container operations; treat that socket as highly privileged.

## Usage Examples

Network diagnostics:

```text
ping 192.168.1.1
troubleshoot github
scan ports on 192.168.1.10
discover hosts on 192.168.1.0/24
what network is this machine on?
```

Local host and container checks:

```text
why is plex down?
check docker containers
parse through logs for errors
bash docker ps
bash systemctl status nginx
```

Current documentation lookup:

```text
find the latest docs for installing jellyfin with docker compose
search online for the current traefik docker compose labels
```

When a request needs current external information, the agent can plan a `web_search` step. The CLI asks for approval before running the search. If you deny it, the agent records that step as failed and continues with any remaining local steps.

## Safety Model

- Read-only diagnostics can run without prompting when they pass the safe shell validator.
- Risky commands require approval, including `sudo`, package managers, Docker mutations, service changes, file writes, shell chains, redirection, inline scripts, and `web_search`.
- SSH and SCP are blocked by default.
- Vulnerability and port scans are limited to private/local targets unless the user explicitly confirms an external/public target.
- Search results are only used inside the current agent run. They are not written to findings or inventory.
- Audit events are written locally under `runtime-context/audit`.

## Runtime Context

At startup the assistant creates this data-only structure under `NCA_RUNTIME_CONTEXT_DIR`:

```text
runtime-context/
├── audit/              # JSONL audit events
├── findings/           # Daily command observations
├── incidents/          # Human-maintained incident notes
├── inventory/
│   ├── hosts/          # Bounded per-host profiles
│   └── networks/       # Bounded per-network profiles
├── memory/             # Recent chat memory
├── notes/              # Human-maintained notes
└── skills/             # Human-maintained procedures/playbooks
```

These files are plain Markdown or JSONL. The assistant writes compact observations and preserves human-maintained inventory notes where supported.

## Project Layout

```text
src/
├── agent.py             # Interactive agent facade
├── agent_executor.py    # Executes planned steps and reviews observations
├── agent_planner.py     # Deterministic and model-assisted planning
├── agent_prompts.py     # Planner and observer prompts
├── bash_tool.py         # Policy-checked shell execution
├── core_functions.py    # Public tool exports
├── dispatcher.py        # Single-function command parser path
├── findings.py          # Findings writer and result summaries
├── knowledgebase.py     # Runtime context and inventory updates
├── llm_providers.py     # OpenAI-compatible and Gemini adapters
├── policy.py            # Editable command approval policy
├── search.py            # SearXNG and Brave Search providers
├── network/             # Ping, traceroute, DNS, discovery, scans
├── validation/          # Input and network target validation
├── formatting/          # Terminal output helpers
└── error_handling/      # Error helpers
```

Tests live in `tests/`.

## Development

Run the test suite:

```bash
pytest -p no:cacheprovider
```

The `-p no:cacheprovider` flag avoids pytest cache writes in restricted workspaces.

When adding a new tool:

1. Add one small function with a structured `dict` result.
2. Export it from `src/core_functions.py` if the agent should call it.
3. Add planning or prompt guidance only if needed.
4. Decide whether results should update findings/inventory.
5. Add focused tests for planning, execution, policy, and failure behavior.

## License

MIT. See `LICENSE`.
