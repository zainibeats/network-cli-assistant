# src/core_functions.py

"""
Core networking functions that the AI assistant can execute.

Each function in this module represents a distinct capability,
like running a command on a remote host or generating a configuration snippet.
"""

from typing import Literal
import xml.etree.ElementTree as ET
import subprocess
import socket
from .utils import validate_ip

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
    if not validate_ip(src_ip) or not validate_ip(dst_ip):
        return {"success": False, "error": "Invalid source or destination IP address."}

    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    return {"success": True, "output": acl_rule}

def ping(host: str) -> dict:
    """Pings a host and returns the output."""
    if not validate_ip(host):
        # Also allow hostnames by checking if it's a valid domain-like name
        if '.' not in host:
            return {"success": False, "error": f"Invalid IP address or hostname: {host}"}

    print(f"Pinging host '{host}'...")
    command = ['ping', '-c', '4', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {"success": True, "output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": e.stderr or f"Failed to ping {host}."}

def traceroute(host: str) -> dict:
    """Traces the route to a host and returns the output."""
    if not validate_ip(host):
        if '.' not in host:
            return {"success": False, "error": f"Invalid IP address or hostname: {host}"}

    print(f"Tracing route to host '{host}'...")
    command = ['traceroute', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {"success": True, "output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": e.stderr or f"Failed to trace route to {host}."}

def dns_lookup(host: str) -> dict:
    """Performs a DNS lookup for a hostname and returns its IP address."""
    print(f"Performing DNS lookup for host '{host}'...")
    try:
        ip_address = socket.gethostbyname(host)
        return {"stdout": f"The IP address for {host} is {ip_address}", "stderr": "", "exit_code": 0}
    except socket.gaierror as e:
        return {"stdout": "", "stderr": f"Could not resolve host: {e}", "exit_code": 1}

def run_nmap_scan(target: str, top_ports: int = 10) -> dict:
    """
    Runs an nmap scan on the given target and parses the XML output.

    Args:
        target (str): The IP address or subnet to scan.
        top_ports (int): Number of top ports to scan (default: 10).

    Returns:
        dict: Parsed nmap output or error message.
    """
    try:
        cmd = [
            "nmap",
            "-T4",
            "--top-ports", str(top_ports),
            "-oX", "-",  # Output as XML to stdout for easier parsing
            target
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Parse the XML output
        root = ET.fromstring(result.stdout)
        
        parsed_output = []
        # Find host status and iterate through ports
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                ports = host.find('ports')
                if ports is None:
                    continue

                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and (state.get('state') == 'open' or state.get('state') == 'filtered'):
                        port_id = port.get('portid')
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        parsed_output.append({
                            'port': port_id,
                            'state': state.get('state'),
                            'service': service_name
                        })

        if not parsed_output:
            return {"success": True, "output": f"No open ports found among the top {top_ports} on {target}."}

        return {"success": True, "output": parsed_output}
        
    except subprocess.CalledProcessError as e:
        # Nmap exits with an error if the host is down
        if "Host seems down" in e.stderr:
            return {"success": True, "output": f"Host {target} seems to be down."}
        return {"success": False, "error": e.stderr or str(e)}
    except ET.ParseError:
        return {"success": False, "error": "Failed to parse nmap XML output."}
    except Exception as ex:
        return {"success": False, "error": str(ex)}

def run_netstat() -> dict:
    """
    Runs 'netstat -tulpn' to list listening TCP and UDP ports.

    Note: This command may require root privileges to see all processes.

    Returns:
        dict: A dictionary with the command's output or an error message.
    """
    try:
        cmd = ["netstat", "-tulpn"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {"success": True, "output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": e.stderr or str(e)}
    except Exception as ex:
        return {"success": False, "error": str(ex)}
