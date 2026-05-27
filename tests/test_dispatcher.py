from src import dispatcher
from src.llm_providers import extract_json_payload, parse_with_provider, selected_provider


def test_extract_json_payload_handles_plain_json():
    assert extract_json_payload('{"function": "ping", "args": {"host": "example.com"}}') == {
        "function": "ping",
        "args": {"host": "example.com"},
    }


def test_extract_json_payload_handles_json_fence():
    assert extract_json_payload('```json\n{"error": "ambiguous"}\n```') == {
        "error": "ambiguous",
    }


def test_selected_provider_defaults_to_openai_compatible(monkeypatch):
    monkeypatch.delenv("CA_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    assert selected_provider() == "openai-compatible"


def test_gemini_provider_is_not_supported(monkeypatch):
    monkeypatch.setenv("CA_LLM_PROVIDER", "gemini")

    try:
        parse_with_provider("{}")
    except ValueError as exc:
        assert "Unsupported LLM provider: gemini" in str(exc)
    else:
        raise AssertionError("gemini provider should not be supported")


def test_parse_command_validates_unknown_model_function(monkeypatch):
    monkeypatch.setattr(
        dispatcher,
        "parse_with_provider",
        lambda _prompt: {"function": "not_registered", "args": {}},
    )

    result = dispatcher.parse_command("do a thing")

    assert result["error"] == "ai_error"
    assert "Unknown function" in result["message"]


def test_parse_command_accepts_known_llm_function(monkeypatch):
    monkeypatch.setattr(
        dispatcher,
        "parse_with_provider",
        lambda _prompt: {"function": "ping", "args": {"host": "example.com"}},
    )

    assert dispatcher.parse_command("please do the standard reachability check") == {
        "status": "ready",
        "function": "ping",
        "args": {"host": "example.com"},
        "source": "llm",
    }


def test_validate_parsed_command_checks_required_args():
    is_valid, error = dispatcher.validate_parsed_command(
        {
            "function": "ping",
            "args": {},
        }
    )

    assert is_valid is False
    assert error == "Missing required parameter: host"


def test_parse_command_sends_broad_scan_request_to_llm(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dispatcher,
        "parse_with_provider",
        lambda prompt: calls.append(prompt)
        or {
            "function": "run_nmap_scan",
            "args": {"target": "192.168.1.0/24"},
        },
    )

    result = dispatcher.parse_command("scan my network")

    assert calls
    assert result["status"] == "ready"
    assert result["function"] == "run_nmap_scan"
