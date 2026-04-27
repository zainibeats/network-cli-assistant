"""
Network operations module.

This module provides network-related functionality including connectivity testing,
DNS lookups, host discovery, and port scanning.
"""

# Import all network functions to maintain backward compatibility
from .analysis import interpret_nmap_results
from .connectivity import ping, traceroute
from .discovery import discover_hosts
from .dns import dns_lookup
from .scanning import run_netstat, run_nmap_scan

# Export all functions for easy importing
__all__ = [
    "ping",
    "traceroute",
    "dns_lookup",
    "discover_hosts",
    "run_nmap_scan",
    "run_netstat",
    "interpret_nmap_results",
]
