# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

import os
import json
import re
import google.generativeai as genai
from dotenv import load_dotenv
import inspect
from typing import Dict, List, Tuple, Optional
from . import core_functions


# Network terminology mappings for better understanding
NETWORK_TERMINOLOGY = {
    # Common abbreviations and synonyms
    'ip': ['ip address', 'ip addr', 'address'],
    'dns': ['domain name', 'hostname resolution', 'name resolution', 'nslookup', 'dig'],
    'ping': ['icmp', 'echo', 'connectivity test', 'reachability'],
    'trace': ['traceroute', 'tracert', 'route trace', 'path trace'],
    'scan': ['port scan', 'nmap', 'port check', 'service discovery'],
    'acl': ['access control list', 'firewall rule', 'access rule'],
    'ssh': ['remote command', 'execute', 'run command'],
    'netstat': ['listening ports', 'open ports', 'network connections'],
    
    # Action synonyms
    'check': ['test', 'verify', 'examine', 'look at', 'show'],
    'get': ['find', 'lookup', 'resolve', 'discover'],
    'block': ['deny', 'drop', 'reject', 'filter'],
    'allow': ['permit', 'accept', 'enable'],
    
    # Target synonyms
    'server': ['host', 'machine', 'system', 'node'],
    'website': ['site', 'domain', 'url', 'web'],
}

# Common networking patterns
NETWORKING_PATTERNS = [
    # IP address patterns
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'ip_address'),
    # Domain patterns
    (r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b', 'domain'),
    # Port patterns
    (r'\bport\s+(\d{1,5})\b', 'port'),
    (r':(\d{1,5})\b', 'port'),
]


def normalize_input(user_input: str) -> str:
    """
    Normalize user input by expanding abbreviations and common networking terms.
    
    Args:
        user_input: Raw user input string
        
    Returns:
        Normalized input string with expanded terminology
    """
    normalized = user_input.lower().strip()
    
    # Expand common networking abbreviations
    for term, expansions in NETWORK_TERMINOLOGY.items():
        for expansion in expansions:
            if expansion in normalized:
                normalized = normalized.replace(expansion, term)
    
    return normalized


def extract_network_entities(user_input: str) -> Dict[str, List[str]]:
    """
    Extract network entities (IPs, domains, ports) from user input.
    
    Args:
        user_input: User input string
        
    Returns:
        Dictionary containing extracted entities by type
    """
    entities = {
        'ip_addresses': [],
        'domains': [],
        'ports': []
    }
    
    for pattern, entity_type in NETWORKING_PATTERNS:
        matches = re.findall(pattern, user_input, re.IGNORECASE)
        if matches:
            if entity_type == 'ip_address':
                entities['ip_addresses'].extend(matches)
            elif entity_type == 'domain':
                entities['domains'].extend([match[0] if isinstance(match, tuple) else match for match in matches])
            elif entity_type == 'port':
                entities['ports'].extend([match if isinstance(match, str) else match[0] for match in matches])
    
    return entities


def get_enhanced_prompt():
    """
    Generate an enhanced prompt with networking terminology and examples.
    """
    # Get all functions from the core_functions module
    core_function_specs = []
    for name, func in inspect.getmembers(core_functions, inspect.isfunction):
        # Skip private functions
        if name.startswith('_'):
            continue
            
        signature = inspect.signature(func)
        docstring = inspect.getdoc(func)
        
        core_function_specs.append(
            f"Function: {name}{signature}\n\"\"\"{docstring}\"\"\""
        )

    core_functions_str = "\n\n".join(core_function_specs)

    return f"""You are the "brain" of a network CLI assistant with enhanced understanding of networking terminology.

Your task is to translate a user's natural language request into a structured JSON object that calls a specific function.

NETWORKING TERMINOLOGY UNDERSTANDING:
- "ip", "address", "ip address" → use for DNS lookups or IP-related operations
- "ping", "test connectivity", "check if up" → use ping function
- "trace", "traceroute", "path" → use traceroute function  
- "dns", "resolve", "lookup", "nslookup" → use dns_lookup function
- "scan", "port scan", "nmap", "check ports" → use run_nmap_scan function
- "acl", "firewall rule", "block", "allow" → use generate_acl function
- "ssh", "run command", "execute" → use run_command function
- "netstat", "listening ports" → use run_netstat function

HOSTNAME COMPLETION:
- Incomplete hostnames (e.g., 'google', 'github') should be completed with common TLDs (.com, .org, etc.)
- Consider context: 'google' → 'google.com', 'github' → 'github.com'

COMMON INPUT VARIATIONS:
- "what's the ip of google" → dns_lookup with host: "google.com"
- "ping google" → ping with host: "google.com"  
- "trace to 8.8.8.8" → traceroute with host: "8.8.8.8"
- "scan ports on server" → run_nmap_scan with target
- "block 1.2.3.4 from 5.6.7.8" → generate_acl with src_ip, dst_ip, action: "deny"
- "allow traffic from A to B" → generate_acl with action: "permit"
- "check ports on localhost" → run_netstat (no args needed)
- "run netstat on server" → run_command with cmd: "netstat -tulpn"

You have access to the following functions:

{core_functions_str}

Respond with ONLY the JSON object, nothing else. If you cannot determine the intent, respond with:
{{"error": "ambiguous", "suggestions": ["suggestion1", "suggestion2"]}}

Examples:
User: "what is the ip for google"
Response: {{"function": "dns_lookup", "args": {{"host": "google.com"}}}}

User: "ping test to github"  
Response: {{"function": "ping", "args": {{"host": "github.com"}}}}

User: "scan top 20 ports on 192.168.1.1"
Response: {{"function": "run_nmap_scan", "args": {{"target": "192.168.1.1", "top_ports": 20}}}}

The user's request will be provided after the '>>>'.

>>> """


def generate_fallback_suggestions(user_input: str, entities: Dict[str, List[str]]) -> List[str]:
    """
    Generate fallback suggestions when command parsing fails.
    
    Args:
        user_input: Original user input
        entities: Extracted network entities
        
    Returns:
        List of suggested commands
    """
    suggestions = []
    normalized = normalize_input(user_input)
    
    # Check for common networking keywords and suggest appropriate functions
    if any(word in normalized for word in ['ping', 'test', 'connectivity', 'reachable']):
        if entities['ip_addresses'] or entities['domains']:
            target = entities['ip_addresses'][0] if entities['ip_addresses'] else entities['domains'][0]
            suggestions.append(f"ping {target}")
    
    if any(word in normalized for word in ['dns', 'resolve', 'lookup', 'ip']):
        if entities['domains']:
            suggestions.append(f"dns_lookup {entities['domains'][0]}")
        elif entities['ip_addresses']:
            suggestions.append(f"dns_lookup {entities['ip_addresses'][0]}")
    
    if any(word in normalized for word in ['trace', 'route', 'path']):
        if entities['ip_addresses'] or entities['domains']:
            target = entities['ip_addresses'][0] if entities['ip_addresses'] else entities['domains'][0]
            suggestions.append(f"traceroute {target}")
    
    if any(word in normalized for word in ['scan', 'port', 'nmap']):
        if entities['ip_addresses'] or entities['domains']:
            target = entities['ip_addresses'][0] if entities['ip_addresses'] else entities['domains'][0]
            suggestions.append(f"run_nmap_scan {target}")
    
    if any(word in normalized for word in ['block', 'deny', 'allow', 'permit', 'acl']):
        if len(entities['ip_addresses']) >= 2:
            action = 'deny' if any(word in normalized for word in ['block', 'deny']) else 'permit'
            suggestions.append(f"generate_acl from {entities['ip_addresses'][0]} to {entities['ip_addresses'][1]} action {action}")
    
    if any(word in normalized for word in ['netstat', 'listening', 'open ports']):
        suggestions.append("run_netstat")
    
    # Generic suggestions if no specific patterns found
    if not suggestions:
        suggestions = [
            "Try: 'ping <hostname>' to test connectivity",
            "Try: 'dns_lookup <hostname>' to resolve IP address", 
            "Try: 'run_nmap_scan <target>' to scan ports",
            "Try: 'traceroute <hostname>' to trace network path"
        ]
    
    return suggestions[:3]  # Limit to 3 suggestions


load_dotenv()


def parse_command(user_input: str) -> dict:
    """
    Enhanced command parser with better networking terminology understanding.

    Args:
        user_input: The raw string from the user.

    Returns:
        A dictionary representing the function to call and its arguments.
        Returns error dict with suggestions if parsing fails.
    """
    if not user_input or not user_input.strip():
        return {
            "error": "empty_input",
            "message": "Please provide a command",
            "suggestions": [
                "Try: 'ping google.com' to test connectivity",
                "Try: 'dns_lookup example.com' to resolve IP",
                "Try: 'run_nmap_scan 192.168.1.1' to scan ports"
            ]
        }
    
    # Extract network entities for fallback suggestions
    entities = extract_network_entities(user_input)
    
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = get_enhanced_prompt()
        full_prompt = f"{prompt}{user_input}"
        
        response = model.generate_content(full_prompt)
        
        # Clean up the response
        text_response = response.text.strip()
        if text_response.startswith('```json'):
            text_response = text_response[7:-3].strip()
        elif text_response.startswith('```'):
            # Handle other code block formats
            lines = text_response.split('\n')
            if len(lines) > 2:
                text_response = '\n'.join(lines[1:-1])
        
        # Parse the JSON response
        parsed_response = json.loads(text_response)
        
        # Validate the response structure
        if "error" in parsed_response:
            if parsed_response["error"] == "ambiguous":
                # AI indicated ambiguous input, enhance with our suggestions
                ai_suggestions = parsed_response.get("suggestions", [])
                fallback_suggestions = generate_fallback_suggestions(user_input, entities)
                all_suggestions = ai_suggestions + fallback_suggestions
                return {
                    "error": "ambiguous",
                    "message": "Command is ambiguous. Here are some suggestions:",
                    "suggestions": list(dict.fromkeys(all_suggestions))[:5]  # Remove duplicates, limit to 5
                }
        
        # Validate that we have a function and args
        if "function" not in parsed_response:
            raise ValueError("Response missing 'function' field")
        
        if "args" not in parsed_response:
            parsed_response["args"] = {}
        
        # Validate function exists
        if not hasattr(core_functions, parsed_response["function"]):
            raise ValueError(f"Unknown function: {parsed_response['function']}")
        
        return parsed_response
        
    except json.JSONDecodeError as e:
        return {
            "error": "parse_error",
            "message": f"Failed to parse AI response as JSON: {e}",
            "suggestions": generate_fallback_suggestions(user_input, entities)
        }
    except Exception as e:
        return {
            "error": "ai_error", 
            "message": f"AI processing failed: {e}",
            "suggestions": generate_fallback_suggestions(user_input, entities)
        }


def validate_parsed_command(parsed_command: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate a parsed command structure and arguments.
    
    Args:
        parsed_command: The parsed command dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if "error" in parsed_command:
        return True, None  # Error responses are valid
    
    if "function" not in parsed_command:
        return False, "Missing 'function' field"
    
    function_name = parsed_command["function"]
    
    # Check if function exists
    if not hasattr(core_functions, function_name):
        return False, f"Unknown function: {function_name}"
    
    # Get function signature for validation
    func = getattr(core_functions, function_name)
    sig = inspect.signature(func)
    
    args = parsed_command.get("args", {})
    
    # Check required parameters
    for param_name, param in sig.parameters.items():
        if param.default == inspect.Parameter.empty and param_name not in args:
            return False, f"Missing required parameter: {param_name}"
    
    return True, None
