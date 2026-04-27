from src.deterministic_parser import parse_deterministic


def test_parses_ping_without_llm():
    assert parse_deterministic("ping google") == {
        "status": "ready",
        "function": "ping",
        "args": {"host": "google.com"},
        "source": "deterministic",
    }


def test_parses_dns_lookup_without_llm():
    assert parse_deterministic("what is the ip of github") == {
        "status": "ready",
        "function": "dns_lookup",
        "args": {"host": "github.com"},
        "source": "deterministic",
    }


def test_parses_local_ports_without_llm():
    assert parse_deterministic("show listening ports") == {
        "status": "ready",
        "function": "run_netstat",
        "args": {},
        "source": "deterministic",
    }


def test_parses_host_discovery_without_llm():
    assert parse_deterministic("discover hosts on 192.168.1.0/24") == {
        "status": "ready",
        "function": "discover_hosts",
        "args": {"network": "192.168.1.0/24"},
        "source": "deterministic",
    }


def test_parses_specific_port_scan_without_llm():
    assert parse_deterministic("scan ports 22, 80, 443 on 192.168.1.10") == {
        "status": "ready",
        "function": "run_nmap_scan",
        "args": {
            "target": "192.168.1.10",
            "specific_ports": "22,80,443",
        },
        "source": "deterministic",
    }


def test_broad_network_scan_needs_clarification():
    result = parse_deterministic("scan my network")

    assert result["status"] == "needs_clarification"
    assert result["missing"] == ["target_or_network"]


def test_unknown_request_falls_through_to_llm():
    assert parse_deterministic("please investigate suspicious behavior") is None
