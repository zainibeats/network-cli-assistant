"""Network operations exposed to assistant tools."""

from .analysis import interpret_nmap_results
from .connectivity import ping, traceroute
from .discovery import discover_hosts
from .dns import dns_lookup
from .scanning import run_netstat, run_nmap_scan

__all__ = [
    "ping",
    "traceroute",
    "dns_lookup",
    "discover_hosts",
    "run_nmap_scan",
    "run_netstat",
    "interpret_nmap_results",
]
