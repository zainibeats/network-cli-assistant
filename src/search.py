"""Minimal web search providers for agent research steps."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, parse, request

DEFAULT_SEARXNG_URL = "http://127.0.0.1:8080/search"
BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
MAX_QUERY_CHARS = 500
DEFAULT_MAX_RESULTS = 5
MAX_RESULTS = 10


def web_search(query: str, max_results: int = DEFAULT_MAX_RESULTS) -> dict[str, Any]:
    """Search the web using the configured provider and return compact results."""
    normalized_query = _normalize_query(query)
    limit = _normalize_max_results(max_results)
    provider = _selected_provider()

    if provider == "brave":
        result = _search_brave(normalized_query, limit)
    elif provider == "searxng":
        result = _search_searxng(normalized_query, limit)
    else:
        return {
            "success": False,
            "error": f"Unsupported search provider: {provider}",
            "error_type": "unsupported_search_provider",
        }

    result["provider"] = provider
    result["query"] = normalized_query
    result["output"] = _format_results(result.get("results", []))
    return result


def _selected_provider() -> str:
    provider = os.getenv("NCA_SEARCH_PROVIDER", "searxng").strip().lower()
    if provider in {"searx", "searxng"}:
        return "searxng"
    if provider == "brave":
        return "brave"
    return provider


def _search_searxng(query: str, max_results: int) -> dict[str, Any]:
    base_url = os.getenv("NCA_SEARXNG_URL", DEFAULT_SEARXNG_URL).strip()
    params = parse.urlencode({"q": query, "format": "json"})
    separator = "&" if "?" in base_url else "?"
    url = f"{base_url}{separator}{params}"
    req = request.Request(url, headers={"Accept": "application/json"})

    try:
        with request.urlopen(req, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"SearXNG search failed: {exc}", "error_type": "search_failed"}

    results = []
    for item in payload.get("results", [])[:max_results]:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "title": str(item.get("title") or "").strip(),
                "url": str(item.get("url") or "").strip(),
                "snippet": str(item.get("content") or item.get("snippet") or "").strip(),
                "published": str(item.get("publishedDate") or item.get("published_date") or "").strip(),
            }
        )

    return {"success": True, "results": [item for item in results if item["url"]]}


def _search_brave(query: str, max_results: int) -> dict[str, Any]:
    api_key = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
    if not api_key:
        return {
            "success": False,
            "error": "BRAVE_SEARCH_API_KEY is required when NCA_SEARCH_PROVIDER=brave",
            "error_type": "missing_api_key",
        }

    params = parse.urlencode({"q": query, "count": max_results})
    req = request.Request(
        f"{BRAVE_SEARCH_URL}?{params}",
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
        },
    )

    try:
        with request.urlopen(req, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"Brave search failed: {exc}", "error_type": "search_failed"}

    results = []
    for item in payload.get("web", {}).get("results", [])[:max_results]:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "title": str(item.get("title") or "").strip(),
                "url": str(item.get("url") or "").strip(),
                "snippet": str(item.get("description") or "").strip(),
                "published": str(item.get("age") or "").strip(),
            }
        )

    return {"success": True, "results": [item for item in results if item["url"]]}


def _normalize_query(query: str) -> str:
    normalized = " ".join(str(query or "").split())
    if not normalized:
        raise ValueError("Search query cannot be empty")
    if len(normalized) > MAX_QUERY_CHARS:
        return normalized[:MAX_QUERY_CHARS].rstrip()
    return normalized


def _normalize_max_results(value: int) -> int:
    try:
        requested = int(value)
    except (TypeError, ValueError):
        requested = DEFAULT_MAX_RESULTS
    return max(1, min(requested, MAX_RESULTS))


def _format_results(results: list[dict[str, str]]) -> str:
    if not results:
        return "No search results returned."
    lines = []
    for index, item in enumerate(results, start=1):
        lines.append(f"{index}. {item['title'] or item['url']}")
        lines.append(f"   URL: {item['url']}")
        if item.get("published"):
            lines.append(f"   Published: {item['published']}")
        if item.get("snippet"):
            lines.append(f"   Snippet: {item['snippet']}")
    return "\n".join(lines)
