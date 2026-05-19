import json

from src import search


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_web_search_uses_searxng_by_default(monkeypatch):
    requests = []

    def fake_urlopen(req, timeout):
        requests.append((req.full_url, timeout))
        return FakeResponse(
            {
                "results": [
                    {
                        "title": "Jellyfin Docker",
                        "url": "https://jellyfin.org/docs/general/installation/container",
                        "content": "Official container installation docs.",
                    }
                ]
            }
        )

    monkeypatch.delenv("NCA_SEARCH_PROVIDER", raising=False)
    monkeypatch.setattr(search.request, "urlopen", fake_urlopen)

    result = search.web_search("jellyfin docker compose")

    assert result["success"] is True
    assert result["provider"] == "searxng"
    assert "http://127.0.0.1:8080/search?" in requests[0][0]
    assert result["results"][0]["title"] == "Jellyfin Docker"
    assert "jellyfin.org" in result["output"]


def test_web_search_supports_brave(monkeypatch):
    captured_headers = []

    def fake_urlopen(req, timeout):
        captured_headers.append(dict(req.header_items()))
        return FakeResponse(
            {
                "web": {
                    "results": [
                        {
                            "title": "Brave result",
                            "url": "https://example.com",
                            "description": "Result description",
                        }
                    ]
                }
            }
        )

    monkeypatch.setenv("NCA_SEARCH_PROVIDER", "brave")
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    monkeypatch.setattr(search.request, "urlopen", fake_urlopen)

    result = search.web_search("example")

    assert result["success"] is True
    assert result["provider"] == "brave"
    assert captured_headers[0]["X-subscription-token"] == "test-key"
    assert result["results"][0]["snippet"] == "Result description"


def test_brave_requires_api_key(monkeypatch):
    monkeypatch.setenv("NCA_SEARCH_PROVIDER", "brave")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)

    result = search.web_search("example")

    assert result["success"] is False
    assert result["error_type"] == "missing_api_key"
