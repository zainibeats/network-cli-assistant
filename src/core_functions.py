# src/core_functions.py

"""
Core networking functions that the AI assistant can execute.

Each function in this module represents a distinct capability,
like running a command on a remote host or generating a configuration snippet.
"""

from typing import Literal

import subprocess
import platform
import socket

def run_command(host: str, cmd: str) -> dict:
    """
    Connects to a remote host via SSH and executes a shell command.

    Args:
        host: The hostname or IP address of the target server.
        cmd: The command to execute on the remote server.

    Returns:
        A dictionary containing the command's output, errors, and exit code.
    """
    # This is a placeholder for a real SSH implementation using a library like paramiko
    print(f"(Placeholder) Executing '{cmd}' on host '{host}' via SSH...")
    return {
        "stdout": f"Placeholder output for '{cmd}' on {host}",
        "stderr": "",
        "exit_code": 0
    }

def generate_acl(src_ip: str, dst_ip: str, action: Literal["permit", "deny"]) -> dict:
    """
    Generates a Cisco-style Access Control List (ACL) rule.

    Args:
        src_ip: The source IP address to match.
        dst_ip: The destination IP address to match.
        action: Whether to 'permit' or 'deny' the traffic.

    Returns:
        A dictionary containing the generated ACL configuration line.
    """
    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    return {"acl_rule": acl_rule}

def ping(host: str) -> dict:
    """Pings a host and returns the output."""
    print(f"Pinging host '{host}'...")
    # Use '-n' for Windows, '-c' for others
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', host]
    result = subprocess.run(command, capture_output=True, text=True)
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode
    }

def traceroute(host: str) -> dict:
    """Traces the route to a host and returns the output."""
    print(f"Tracing route to host '{host}'...")
    command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', host]
    result = subprocess.run(command, capture_output=True, text=True)
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode
    }

def dns_lookup(host: str) -> dict:
    """Performs a DNS lookup for a host and returns the IP address."""
    print(f"Performing DNS lookup for host '{host}'...")
    try:
        ip_address = socket.gethostbyname(host)
        return {"stdout": f"The IP address for {host} is {ip_address}", "stderr": "", "exit_code": 0}
    except socket.gaierror as e:
        return {"stdout": "", "stderr": f"Could not resolve host: {e}", "exit_code": 1}
