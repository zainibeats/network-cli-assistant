"""Tool functions the assistant may execute."""

from .network import discover_hosts, dns_lookup, ping, run_netstat, run_nmap_scan, traceroute
from .search import web_search

__all__ = [
    "ping",
    "traceroute",
    "dns_lookup",
    "discover_hosts",
    "run_nmap_scan",
    "run_netstat",
    "web_search",
]
