"""
Core networking functions that the AI assistant can execute.

This module now serves as a compatibility layer, importing all functions
from the new modular structure to maintain backward compatibility.
"""

# Import all functions from the new modular structure
from .network import discover_hosts, dns_lookup, ping, run_netstat, run_nmap_scan, traceroute
from .search import web_search

# Export all functions to maintain backward compatibility
__all__ = [
    "ping",
    "traceroute",
    "dns_lookup",
    "discover_hosts",
    "run_nmap_scan",
    "run_netstat",
    "web_search",
]
