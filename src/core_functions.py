"""
Core networking functions that the AI assistant can execute.

This module now serves as a compatibility layer, importing all functions
from the new modular structure to maintain backward compatibility.
"""

# Import all functions from the new modular structure
from .network import (
    run_command,
    generate_acl,
    ping,
    traceroute,
    dns_lookup,
    discover_hosts,
    run_nmap_scan,
    run_netstat
)

# Export all functions to maintain backward compatibility
__all__ = [
    'run_command',
    'generate_acl',
    'ping',
    'traceroute',
    'dns_lookup',
    'discover_hosts',
    'run_nmap_scan',
    'run_netstat'
]