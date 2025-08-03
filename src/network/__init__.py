"""
Network operations module.

This module provides network-related functionality including connectivity testing, 
DNS lookups, host discovery, and port scanning.
"""

# Import all network functions to maintain backward compatibility
from .connectivity import ping, traceroute
from .dns import dns_lookup
from .discovery import discover_hosts
from .scanning import run_nmap_scan, run_netstat
from .analysis import interpret_nmap_results

# Export all functions for easy importing
__all__ = [
    'ping',
    'traceroute',
    'dns_lookup',
    'discover_hosts',
    'run_nmap_scan',
    'run_netstat',
    'interpret_nmap_results'
]