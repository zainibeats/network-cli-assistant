"""
Network operations module.

This module provides all network-related functionality including SSH commands,
ACL generation, connectivity testing, DNS lookups, host discovery, and port scanning.
"""

# Import all network functions to maintain backward compatibility
from .ssh import run_command
from .acl import generate_acl
from .connectivity import ping, traceroute
from .dns import dns_lookup
from .discovery import discover_hosts
from .scanning import run_nmap_scan, run_netstat
from .analysis import interpret_nmap_results

# Export all functions for easy importing
__all__ = [
    'run_command',
    'generate_acl', 
    'ping',
    'traceroute',
    'dns_lookup',
    'discover_hosts',
    'run_nmap_scan',
    'run_netstat',
    'interpret_nmap_results'
]