from src import agent
from src.agent import build_agent_plan, execute_agent_plan, handle_agent_message


def test_builds_host_diagnostic_plan():
    plan = build_agent_plan("investigate server 192.168.1.10")

    assert plan["status"] == "agent_plan"
    assert plan["mode"] == "safe"
    assert plan["target"] == "192.168.1.10"
    assert [step["function"] for step in plan["steps"]] == [
        "ping",
        "traceroute",
        "run_nmap_scan",
    ]


def test_builds_hostname_plan_with_dns_lookup():
    plan = build_agent_plan("troubleshoot github")

    assert plan["target"] == "github.com"
    assert plan["steps"][0] == {
        "function": "dns_lookup",
        "args": {"host": "github.com"},
        "reason": "Resolve the hostname",
    }


def test_broad_agent_request_needs_clarification():
    result = build_agent_plan("investigate my network")

    assert result["status"] == "needs_clarification"
    assert result["missing"] == ["target_or_network"]


def test_large_network_plan_needs_narrower_scope():
    result = build_agent_plan("diagnose network 10.0.0.0/16")

    assert result["status"] == "needs_clarification"
    assert result["missing"] == ["narrower_network"]


def test_builds_localhost_security_audit_plan():
    plan = build_agent_plan("scan localhost for vulnerabilities")

    assert plan["status"] == "agent_plan"
    assert plan["target"] == "localhost"
    assert [step["function"] for step in plan["steps"]] == [
        "run_bash",
        "run_bash",
        "run_nmap_scan",
    ]
    assert plan["steps"][0]["args"] == {"command": "ss -tulpen"}


def test_builds_local_network_context_plan():
    plan = build_agent_plan("what network is the machine on?")

    assert plan["status"] == "agent_plan"
    assert plan["target"] == "local-machine"
    assert [step["function"] for step in plan["steps"]] == [
        "run_bash",
        "run_bash",
        "run_bash",
    ]
    assert plan["steps"][0]["args"] == {"command": "ip -brief -4 addr show scope global"}
    assert plan["steps"][1]["args"] == {"command": "ip route show"}


def test_builds_local_log_review_plan():
    plan = build_agent_plan("parse through logs for errors")

    assert plan["status"] == "agent_plan"
    assert plan["target"] == "local-logs"
    assert [step["args"] for step in plan["steps"]] == [
        {"command": "journalctl -n 200 -p warning"},
        {"command": "systemctl --failed"},
    ]


def test_builds_remote_host_security_audit_plan():
    plan = build_agent_plan("scan 192.168.1.20 for vulnerabilities")

    assert plan["status"] == "agent_plan"
    assert plan["target"] == "192.168.1.20"
    assert [step["function"] for step in plan["steps"]] == [
        "ping",
        "traceroute",
        "run_nmap_scan",
    ]
    assert plan["steps"][-1]["args"] == {"target": "192.168.1.20", "top_ports": 100}


def test_builds_network_security_audit_plan():
    plan = build_agent_plan("security check network 192.168.1.0/24")

    assert plan["status"] == "agent_plan"
    assert plan["target"] == "192.168.1.0/24"
    assert [step["function"] for step in plan["steps"]] == [
        "discover_hosts",
        "run_nmap_scan",
    ]
    assert plan["steps"][-1]["args"] == {"target": "192.168.1.0/24", "top_ports": 100}


def test_named_homelab_server_without_target_needs_clarification():
    result = build_agent_plan("scan my ubuntu server for vulnerabilities")

    assert result["status"] == "needs_clarification"
    assert result["missing"] == ["target_or_network"]


def test_execute_agent_plan_uses_only_planned_functions():
    calls = []

    def fake_resolver(name):
        def fake_function(**kwargs):
            calls.append((name, kwargs))
            return {"success": True, "stdout": f"{name} ok"}

        return fake_function

    plan = build_agent_plan("investigate server 192.168.1.10")
    result = execute_agent_plan(
        plan,
        function_resolver=fake_resolver,
        finding_recorder=lambda _command, _result: None,
        inventory_updater=lambda _command, _result: None,
    )

    assert result["agent"] is True
    assert result["mode"] == "safe"
    assert calls == [
        ("ping", {"host": "192.168.1.10"}),
        ("traceroute", {"host": "192.168.1.10"}),
        ("run_nmap_scan", {"target": "192.168.1.10", "top_ports": 10}),
    ]


def test_execute_agent_plan_runs_bash_steps(monkeypatch):
    bash_calls = []
    function_calls = []

    monkeypatch.setattr(
        agent,
        "run_bash",
        lambda **kwargs: bash_calls.append(kwargs) or {"success": True, "stdout": "bash ok"},
    )

    def fake_resolver(name):
        def fake_function(**kwargs):
            function_calls.append((name, kwargs))
            return {"success": True, "stdout": f"{name} ok"}

        return fake_function

    result = execute_agent_plan(
        build_agent_plan("scan localhost for vulnerabilities"),
        function_resolver=fake_resolver,
        finding_recorder=lambda _command, _result: None,
        inventory_updater=lambda _command, _result: None,
    )

    assert result["agent"] is True
    assert bash_calls == [{"command": "ss -tulpen"}, {"command": "ip addr show"}]
    assert function_calls == [("run_nmap_scan", {"target": "localhost", "top_ports": 100})]


def test_handle_agent_message_uses_diagnostic_plan(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "append_chat_turn", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(
        agent,
        "execute_agent_plan",
        lambda plan, **_kwargs: {
            "success": True,
            "agent": True,
            "target": plan["target"],
            "output": "planned",
        },
    )

    response = handle_agent_message("investigate server 192.168.1.10")

    assert "planned" in response


def test_handle_agent_message_routes_parsed_command_through_agent(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "append_chat_turn", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(
        agent,
        "execute_agent_plan",
        lambda plan, **_kwargs: {
            "success": True,
            "agent": True,
            "target": plan["target"],
            "output": f"agent ran {plan['steps'][0]['function']}",
        },
    )

    response = handle_agent_message("ping 192.168.1.1")

    assert "agent ran ping" in response


def test_handle_agent_message_runs_bash_prefix(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "append_chat_turn", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(
        agent,
        "execute_agent_plan",
        lambda plan, **_kwargs: {
            "success": True,
            "agent": True,
            "target": plan["target"],
            "output": f"agent ran {plan['steps'][0]['args']['command']}",
        },
    )

    response = handle_agent_message("bash ip addr show")

    assert "agent ran ip addr show" in response


def test_handle_agent_message_does_not_fall_back_to_chat_for_parser_error(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "append_chat_turn", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(agent, "parse_command", lambda _user_input: {"status": "error", "error": "ambiguous"})
    monkeypatch.setattr(agent, "chat_with_provider", lambda _prompt, user_input: f"chat {user_input}")

    response = handle_agent_message("remember that the router is in the closet")

    assert "Could not understand command" in response


def test_build_shell_agent_plan_uses_model_commands(monkeypatch):
    monkeypatch.setattr(
        agent,
        "parse_json_with_provider",
        lambda _system, _user: {
            "target": "local-machine",
            "commands": [
                {"command": "systemctl status plexmediaserver", "reason": "Check service state"},
                {"command": "journalctl -u plexmediaserver -n 80 --no-pager", "reason": "Read logs"},
            ],
        },
    )
    monkeypatch.setattr(agent, "load_chat_memory", lambda: "")

    plan = agent.build_shell_agent_plan("why is plex down?")

    assert plan["status"] == "agent_plan"
    assert plan["source"] == "llm_shell_planner"
    assert [step["args"]["command"] for step in plan["steps"]] == [
        "systemctl status plexmediaserver",
        "journalctl -u plexmediaserver -n 80 --no-pager",
    ]


def test_build_shell_agent_plan_requires_external_scan_confirmation(monkeypatch):
    monkeypatch.setattr(
        agent,
        "parse_json_with_provider",
        lambda _system, _user: {
            "target": "scanme.nmap.org",
            "commands": [{"command": "nmap scanme.nmap.org", "reason": "Scan external host"}],
        },
    )
    monkeypatch.setattr(agent, "load_chat_memory", lambda: "")

    result = agent.build_shell_agent_plan("scan scanme.nmap.org for vulnerabilities")

    assert result["status"] == "needs_clarification"
    assert result["missing"] == ["external_scan_confirmation"]


def test_execute_agent_plan_asks_approval_for_non_read_only_bash(monkeypatch):
    calls = []
    monkeypatch.setattr(
        agent,
        "run_bash",
        lambda **kwargs: calls.append(kwargs) or {"success": True, "stdout": "approved"},
    )
    plan = {
        "status": "agent_plan",
        "mode": "power",
        "target": "local-machine",
        "steps": [
            {
                "function": "run_bash",
                "args": {"command": "systemctl restart plexmediaserver"},
                "reason": "Restart service",
            }
        ],
    }

    result = execute_agent_plan(
        plan,
        finding_recorder=lambda _command, _result: None,
        inventory_updater=lambda _command, _result: None,
        approval_callback=lambda command, reason: command.startswith("systemctl") and bool(reason),
    )

    assert result["agent"] is True
    assert calls == [
        {"command": "systemctl restart plexmediaserver", "timeout": 30, "require_safe": False}
    ]


def test_execute_agent_plan_includes_command_output(monkeypatch):
    monkeypatch.setattr(
        agent,
        "run_bash",
        lambda **_kwargs: {
            "success": True,
            "command": "nmap -Pn 172.23.51.30",
            "stdout": "\n".join(
                [
                    "Starting Nmap",
                    "PORT     STATE SERVICE",
                    "22/tcp   open  ssh",
                    "32400/tcp open  plex",
                ]
            ),
            "exit_code": 0,
            "output": "PORT     STATE SERVICE\n22/tcp open ssh\n32400/tcp open plex",
        },
    )

    result = execute_agent_plan(
        {
            "status": "agent_plan",
            "mode": "power",
            "target": "172.23.51.30",
            "steps": [
                {
                    "function": "run_bash",
                    "args": {"command": "nmap -Pn 172.23.51.30"},
                    "reason": "Scan requested host",
                }
            ],
        },
        finding_recorder=lambda _command, _result: None,
        inventory_updater=lambda _command, _result: None,
    )

    assert "$ nmap -Pn 172.23.51.30" in result["output"]
    assert "22/tcp   open  ssh" in result["output"]
    assert "32400/tcp open  plex" in result["output"]


def test_execute_agent_plan_can_run_model_followup(monkeypatch):
    calls = []
    reviews = iter(
        [
            {
                "commands": [
                    {
                        "command": "journalctl -u plexmediaserver -n 50 --no-pager",
                        "reason": "Read service errors",
                    }
                ]
            },
            {"answer": "Plex is listening, but logs show a permissions error."},
        ]
    )

    monkeypatch.setattr(agent, "parse_json_with_provider", lambda *_args: next(reviews))
    monkeypatch.setattr(
        agent,
        "run_bash",
        lambda command, **_kwargs: calls.append(command)
        or {"success": True, "stdout": f"output for {command}", "exit_code": 0},
    )

    result = execute_agent_plan(
        {
            "status": "agent_plan",
            "mode": "power",
            "target": "local-machine",
            "steps": [
                {
                    "function": "run_bash",
                    "args": {"command": "systemctl status plexmediaserver"},
                    "reason": "Check state",
                }
            ],
        },
        finding_recorder=lambda _command, _result: None,
        inventory_updater=lambda _command, _result: None,
        user_input="why is plex down?",
        observe_with_model=True,
    )

    assert calls == [
        "systemctl status plexmediaserver",
        "journalctl -u plexmediaserver -n 50 --no-pager",
    ]
    assert "Plex is listening" in result["output"]
