# AI Context File

> This document is for IDE AI assistants (e.g., Windsurf Cascade, Cline, Github Copilot). It acts like a README specifically for the AI agent, helping it understand the intent, structure, and constraints of this project while developing inside the code editor of your choice.

---

## 🧠 Project Purpose

Build a **CLI Assistant for Common Network Tasks** that:

* Responds to natural-language input like:

  * “show me port status on server X”
  * “generate Cisco ACL to block IP Y”
* Converts intent into structured function calls (e.g., `run_command`, `generate_acl`)
* Executes those functions (e.g., via SSH or config generation)
* Summarizes the output and suggests next steps

---

## 🧱 System Prompts (Behavior Guidelines)

### ✅ Core Style & Safety Rules

* **Use the latest stable versions** of Python dependencies
* **Follow PEP 8** and standard code conventions
* **Prefer pure‑Python stdlib** where possible (except for specialized needs like `paramiko` for SSH)
* **Avoid hard‑coding sensitive info** (e.g. passwords, API keys)
* **Validate all generated code** (JSON, YAML, ACLs, schemas)
* **Ask clarifying questions** if the user’s intent is ambiguous
* **Offer commentary or follow‑ups** after function execution

### 🧠 Simplicity & “Less Is More”

* **Less is always more.** Start with the simplest working version; avoid premature abstraction or unnecessary layers.
* **Favor standard patterns** over clever one‑offs—readability and maintainability win every time.
* **If there’s a one‑line stdlib solution, use it** rather than pulling in a heavy third‑party package.

### 📋 Plan‑Before‑You‑Code

1. **Summarize your approach** in 2–4 bullet points before writing any code.
2. **Wait for user confirmation** (or adjustments) to ensure alignment.
3. **Break features into small steps**: design → code → test → review.

### 🧪 Testing & Iteration

* **Write/tests as you go**: unit tests for each small chunk, integration tests for workflows.
* **Run quick validation** (lint, type‐check, schema‐parse) after every AI‑generated snippet.
* **Checkpoint with Git** before risky refactors; allows easy rollback if complexity creeps in.

### 🔒 Security & Secrets

* **Strip or flag secrets**: never generate code with embedded credentials, and remind the user to configure secure storage (env vars, vaults).
* **Scan for common vulnerabilities** (injection, unsafe deserialization, missing auth) and warn proactively.
* **Embed security best‑practices** by default—e.g. parameterized queries, safe file‐handling.

### 🧩 Maintainability & Structure

* **Modularize relentlessly**: one responsibility per file or function, clear input/output contracts.
* **Refactor continuously**: prune dead code, rename confusing identifiers, simplify complex logic.
* **Document succinctly**: docstrings for public APIs, README to outline high‑level project conventions.

### 💬 Communication & Transparency

* **Explain after you code**: once code’s produced, summarize what changed and why, and suggest next steps (tests, docs, deployment).
* **Offer alternate “lighter” approaches** when you’ve chosen a heavier solution.
* **Invite feedback**: “Is this direction working for you? Would you like adjustments before moving on?”

#### Example Runtime Flow

1. **Plan**: “I’ll implement X by defining a small helper in pure stdlib, then wiring it into your existing service. Confirm?”
2. **Code**: generate the helper; run lint/type‑check.
3. **Explain**: “Here’s what I built and how to test it…”
4. **Test**: provide a simple pytest snippet.
5. **Secure‑check**: “All inputs are validated; consider storing your DB URL in an env var.”
6. **Iterate**: “Would you like to add logging or keep it minimal for now?”

---

## 🔧 Core Functions

These are the key Python functions exposed for AI use:

```python
run_command(host: str, cmd: str) -> dict
# Connect via SSH and run a shell command on a remote host

generate_acl(src_ip: str, dst_ip: str, action: Literal["permit", "deny"]) -> dict
# Create a Cisco ACL rule to allow or block traffic
```

The AI should recommend structured calls to these functions based on natural language input, like:

```json
{
  "command": "run_command",
  "host": "192.0.2.10",
  "cmd": "netstat -tulnp"
}
```

---

## 🧑‍💻 Development Goals

* Focus on extensibility: AI should anticipate more functions (e.g., `ping`, `traceroute`, `check_dns`)
* Make all generated code production-quality and readable
* Favor stateless functional code
* Limit assumptions: confirm server access, IP ranges, and actions if unclear

---

## ✅ Example Prompts & Responses

**User:** *"What ports are open on server 10.1.1.1?"*

**AI Suggestion:**

```json
{
  "command": "run_command",
  "host": "10.1.1.1",
  "cmd": "netstat -tulnp"
}
```

---

**User:** *"Block 203.0.113.45 from reaching 192.0.2.10"*

**AI Suggestion:**

```json
{
  "command": "generate_acl",
  "src_ip": "203.0.113.45",
  "dst_ip": "192.0.2.10",
  "action": "deny"
}
```
