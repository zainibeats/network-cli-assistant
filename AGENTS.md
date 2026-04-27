# AGENTS.md

## Rules for Agent

- Always keep your responses concise to the user
- Always signal me when it's time to compact the context (/compact) and/or when you are ready to agentically work on your own (i.e. spin up sub-agents, write/use skills, search online, etc without human interaction).
- Use the latest stable versions of packages
- Never hard‑code sensitive info
- Ask clarifying questions if the user’s intent is ambiguous
- Less is always more. Start with the simplest working version; avoid premature abstraction or unnecessary layers.
- Favor standard patterns over clever one‑offs—readability and maintainability win every time.
- Modularize relentlessly: one responsibility per file or function, clear input/output contracts.
- Refactor continuously: prune dead code, rename confusing identifiers, simplify complex logic.
- Document succinctly: docstrings for public APIs, README to outline high‑level project conventions.

## Project Direction Preferences

- Prefer cleanup, refactoring, and testability before adding large new features.
- Behavior changes are acceptable when they make the assistant safer, clearer, or more efficient.
- The LLM should not do heavy network work. It should map natural language to approved functions/tools, ask clarifying questions when needed, and summarize hard-to-read output.
- Favor deterministic command routing before LLM fallback for common requests.
- Broad, risky, or destructive operations should clarify or confirm scope first unless the assistant can infer safe local context through an approved simple command.
- Runtime assistant context should be optimized for small local models.
- Prefer plain Markdown with predictable templates for runtime memory, findings, inventory, incidents, and skills.
- Runtime findings should be written automatically.
- Findings/notes directories must never be executable; production may mount an external notes directory such as Obsidian into the Docker container.
- Keep stable role/purpose/alignment context separate from writable notes and findings, ideally protected by convention or read-only mounting.
