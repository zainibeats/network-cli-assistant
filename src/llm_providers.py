"""Model provider adapters for command parsing and local agent reasoning."""

import json
import os
from urllib import error, request

DEFAULT_LOCAL_MODEL = "local-model"
DEFAULT_LOCAL_BASE_URL = "http://127.0.0.1:1234/v1"


def selected_provider() -> str:
    """Return the configured model provider."""
    provider = os.getenv("CA_LLM_PROVIDER") or os.getenv("LLM_PROVIDER")
    if provider:
        return provider.strip().lower()
    return "openai-compatible"


def extract_json_payload(text_response: str) -> dict:
    """Parse a JSON object returned by a model, with light code-fence cleanup."""
    text_response = text_response.strip()
    if text_response.startswith("```json"):
        text_response = text_response[7:-3].strip()
    elif text_response.startswith("```"):
        lines = text_response.split("\n")
        if len(lines) > 2:
            text_response = "\n".join(lines[1:-1]).strip()

    return json.loads(text_response)


def parse_with_openai_compatible(full_prompt: str) -> dict:
    """Parse user intent with an OpenAI-compatible local endpoint."""
    base_url = (
        os.getenv("OPENAI_COMPATIBLE_BASE_URL")
        or os.getenv("CA_OPENAI_BASE_URL")
        or DEFAULT_LOCAL_BASE_URL
    ).rstrip("/")
    model_name = os.getenv("CA_LLM_MODEL") or os.getenv("LLM_MODEL") or DEFAULT_LOCAL_MODEL
    api_key = os.getenv("OPENAI_COMPATIBLE_API_KEY") or os.getenv("CA_OPENAI_API_KEY") or "local"

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": full_prompt},
            {"role": "user", "content": "Return only the JSON object."},
        ],
        "temperature": 0,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    req = request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(f"Local model request failed: {exc}") from exc

    content = data["choices"][0]["message"]["content"]
    return extract_json_payload(content)


def chat_with_openai_compatible(system_prompt: str, user_prompt: str, *, temperature: float = 0) -> str:
    """Send a chat request to an OpenAI-compatible local endpoint."""
    base_url = (
        os.getenv("OPENAI_COMPATIBLE_BASE_URL")
        or os.getenv("CA_OPENAI_BASE_URL")
        or DEFAULT_LOCAL_BASE_URL
    ).rstrip("/")
    model_name = os.getenv("CA_LLM_MODEL") or os.getenv("LLM_MODEL") or DEFAULT_LOCAL_MODEL
    api_key = os.getenv("OPENAI_COMPATIBLE_API_KEY") or os.getenv("CA_OPENAI_API_KEY") or "local"

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    req = request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(f"Local model request failed: {exc}") from exc

    return data["choices"][0]["message"]["content"].strip()


def parse_with_provider(full_prompt: str) -> dict:
    """Route prompt parsing to the configured model provider."""
    provider = selected_provider()
    if provider in {"openai-compatible", "local", "lmstudio", "ollama"}:
        return parse_with_openai_compatible(full_prompt)
    raise ValueError(f"Unsupported LLM provider: {provider}")


def chat_with_provider(system_prompt: str, user_prompt: str, *, temperature: float = 0) -> str:
    """Route a general chat request to the configured model provider."""
    provider = selected_provider()
    if provider in {"openai-compatible", "local", "lmstudio", "ollama"}:
        return chat_with_openai_compatible(system_prompt, user_prompt, temperature=temperature)
    raise ValueError(f"Unsupported LLM provider: {provider}")


def parse_json_with_provider(system_prompt: str, user_prompt: str) -> dict:
    """Ask the provider for a JSON object and parse the response."""
    return extract_json_payload(chat_with_provider(system_prompt, user_prompt, temperature=0))
