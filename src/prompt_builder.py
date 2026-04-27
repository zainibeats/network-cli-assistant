"""Prompt construction for command parsing."""

from .command_catalog import get_function_specs


def build_command_parser_prompt() -> str:
    """Generate the prompt used to map natural language to tool calls."""
    prompt = "You are a network CLI assistant command parser.\n\n"
    prompt += "Your task is to translate a user's natural language request into a structured JSON object that calls a specific function.\n\n"
    prompt += "You have access to the following functions:\n\n"
    prompt += get_function_specs() + "\n\n"
    prompt += "The assistant runs tools on the user's own network for defensive administration and investigation.\n"
    prompt += "Never invent shell commands. Only select one listed function and arguments.\n"
    prompt += "If the request could be destructive, broad, or unclear, return ambiguous.\n\n"
    prompt += 'IMPORTANT: When users mention domain names without TLDs (like "google", "mullvad", "github"), use your knowledge to provide the correct full domain name:\n'
    prompt += '- "google" -> "google.com"\n'
    prompt += '- "mullvad" -> "mullvad.net"\n'
    prompt += '- "github" -> "github.com"\n'
    prompt += '- "wikipedia" -> "wikipedia.org"\n'
    prompt += '- "archive" -> "archive.org"\n'
    prompt += '- "reddit" -> "reddit.com"\n'
    prompt += '- "stackoverflow" -> "stackoverflow.com"\n'
    prompt += "- etc.\n\n"
    prompt += "Use your training data knowledge of well-known websites and services to determine the correct TLD.\n\n"
    prompt += "NETWORK OPERATIONS: Choose the right function based on user intent:\n\n"
    prompt += "HOST DISCOVERY (finding active IPs):\n"
    prompt += '- For "what IPs are being used", "what hosts are up", "what machines are active": use discover_hosts\n'
    prompt += '- Example: "what IPs are being used on network 192.168.1.0/24" -> {"function": "discover_hosts", "args": {"network": "192.168.1.0/24"}}\n'
    prompt += '- Example: "what machines are up on 10.0.0.0/16" -> {"function": "discover_hosts", "args": {"network": "10.0.0.0/16"}}\n\n'
    prompt += "PORT SCANNING (finding open services):\n"
    prompt += '- For "what ports are open", "scan ports", "check services": use run_nmap_scan\n'
    prompt += '- Example: "what ports are open on network 192.168.1.0/24" -> {"function": "run_nmap_scan", "args": {"target": "192.168.1.0/24"}}\n'
    prompt += '- Example: "scan ports on 192.168.1.1" -> {"function": "run_nmap_scan", "args": {"target": "192.168.1.1"}}\n\n'
    prompt += "Respond with ONLY the JSON object in this exact format:\n"
    prompt += '{"function": "function_name", "args": {"param1": "value1", "param2": "value2"}}\n\n'
    prompt += "For example:\n"
    prompt += '- For "ping google": {"function": "ping", "args": {"host": "google.com"}}\n'
    prompt += '- For "what is the ip of mullvad": {"function": "dns_lookup", "args": {"host": "mullvad.net"}}\n'
    prompt += '- For "lookup DNS for github": {"function": "dns_lookup", "args": {"host": "github.com"}}\n'
    prompt += '- For "scan ports on 192.168.1.1": {"function": "run_nmap_scan", "args": {"target": "192.168.1.1"}}\n'
    prompt += '- For "what ports are open on network 192.168.1.0/24": {"function": "run_nmap_scan", "args": {"target": "192.168.1.0/24"}}\n'
    prompt += '- For "what IPs are being used on network 192.168.1.0/24": {"function": "discover_hosts", "args": {"network": "192.168.1.0/24"}}\n'
    prompt += '- For "what machines are up on 10.0.0.0/16": {"function": "discover_hosts", "args": {"network": "10.0.0.0/16"}}\n\n'
    prompt += "If you cannot determine the intent, respond with:\n"
    prompt += '{"error": "ambiguous"}\n\n'
    prompt += "The user's request will be provided after the '>>>'.\n\n"
    prompt += ">>> "

    return prompt
