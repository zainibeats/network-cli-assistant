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
import errno
from .utils import (
    validate_ip, validate_ip_with_details, validate_hostname, validate_target, validate_port,
    create_validation_error, handle_network_timeout, handle_dns_resolution_error,
    handle_connection_refused_error, handle_permission_denied_error, handle_command_not_found_error,
    validate_network_operation_input, retry_network_operation
)

def run_command(host: str, cmd: str) -> dict:
    """
    Connects to a remote host via SSH and executes a shell command.

    Args:
        host: The hostname or IP address of the target server.
        cmd: The command to execute on the remote server.

    Returns:
        A dictionary containing the command's output, errors, and exit code.
    """
    # Validate host parameter
    is_valid_host, error_msg, suggestion = validate_target(host)
    if not is_valid_host:
        return {"success": False, "error": error_msg}
    
    # Validate command parameter
    if not cmd or not isinstance(cmd, str):
        return {"success": False, "error": "Command cannot be empty"}
    
    cmd = cmd.strip()
    if not cmd:
        return {"success": False, "error": "Command cannot be empty"}
    
    # Basic command sanitization - prevent obvious injection attempts
    dangerous_patterns = [';', '&&', '||', '|', '>', '>>', '<', '`', '$()']
    if any(pattern in cmd for pattern in dangerous_patterns):
        return {
            "success": False,
            "error": "Command contains potentially dangerous characters",
            "error_type": "security_violation"
        }
    
    # This is a placeholder for a real SSH implementation using a library like paramiko
    print(f"(Placeholder) Executing '{cmd}' on host '{host}' via SSH...")
    return {
        "success": True,
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
    # Validate source IP address
    is_valid_src, src_error, src_suggestion = validate_ip_with_details(src_ip)
    if not is_valid_src:
        return {"success": False, "error": src_error}
    
    # Validate destination IP address
    is_valid_dst, dst_error, dst_suggestion = validate_ip_with_details(dst_ip)
    if not is_valid_dst:
        return {"success": False, "error": dst_error}
    
    # Validate action parameter
    if not action or action not in ["permit", "deny"]:
        return {"success": False, "error": "Action must be either 'permit' or 'deny'"}

    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    return {"success": True, "output": acl_rule}

def ping(host: str) -> dict:
    """
    Pings a host to test network connectivity and measure response times.
    
    Args:
        host: The hostname or IP address to ping
        
    Returns:
        dict: Contains success status and ping output
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    print(f"Pinging host '{host}'...")
    command = ['ping', '-c', '4', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Ping operation timed out after 30 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            return {
                "success": False,
                "error": f"Network unreachable when trying to ping {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            return {
                "success": False,
                "error": "Permission denied for ping operation",
                "error_type": "permission_denied"
            }
        else:
            return {
                "success": False,
                "error": stderr_output or f"Failed to ping {host}",
                "error_type": "ping_failed"
            }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Ping command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error during ping: {str(e)}",
            "error_type": "unexpected_error"
        }

def traceroute(host: str) -> dict:
    """
    Traces the network path to a destination, showing each router (hop) along the way.
    
    Args:
        host: The hostname or IP address to trace the route to
        
    Returns:
        dict: Contains success status and traceroute output
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    print(f"Tracing network path to '{host}'...")
    command = ['traceroute', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Traceroute operation timed out after 120 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            return {
                "success": False,
                "error": f"Network unreachable when trying to traceroute to {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            return {
                "success": False,
                "error": "Permission denied for traceroute operation",
                "error_type": "permission_denied"
            }
        else:
            return {
                "success": False,
                "error": stderr_output or f"Failed to trace route to {host}",
                "error_type": "traceroute_failed"
            }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Traceroute command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error during traceroute: {str(e)}",
            "error_type": "unexpected_error"
        }

def dns_lookup(host: str) -> dict:
    """
    Performs comprehensive DNS lookups including forward and reverse resolution.
    
    Args:
        host: The hostname or IP address to look up
        
    Returns:
        dict: Contains forward/reverse lookup results
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    print(f"Performing DNS lookup for '{host}'...")
    
    results = {
        "success": True,
        "forward_lookup": None,
        "reverse_lookup": None
    }
    
    # Determine if input is an IP address or hostname
    is_ip_address = validate_ip(host)
    
    try:
        if is_ip_address:
            # Input is IP address - do reverse lookup first, then forward lookup of result
            print(f"Input detected as IP address, performing reverse lookup...")
            try:
                hostname = socket.gethostbyaddr(host)[0]
                results["reverse_lookup"] = {
                    "success": True,
                    "ip_address": host,
                    "hostname": hostname,
                    "explanation": f"IP {host} resolves to hostname {hostname}"
                }
                
                # Now do forward lookup of the resolved hostname
                try:
                    forward_ip = socket.gethostbyname(hostname)
                    results["forward_lookup"] = {
                        "success": True,
                        "hostname": hostname,
                        "ip_address": forward_ip,
                        "explanation": f"Hostname {hostname} resolves to IP {forward_ip}",
                        "consistency_check": forward_ip == host
                    }
                    if forward_ip != host:
                        results["forward_lookup"]["warning"] = f"Forward lookup returned different IP ({forward_ip}) than original ({host})"
                except socket.gaierror:
                    results["forward_lookup"] = {
                        "success": False,
                        "error": f"Could not perform forward lookup for resolved hostname {hostname}"
                    }
                    
            except socket.gaierror as e:
                results["reverse_lookup"] = {
                    "success": False,
                    "ip_address": host,
                    "error": f"Could not perform reverse lookup: {e}"
                }
                results["success"] = False
                
        else:
            # Input is hostname - do forward lookup first, then reverse lookup of result
            print(f"Input detected as hostname, performing forward lookup...")
            try:
                ip_address = socket.gethostbyname(host)
                results["forward_lookup"] = {
                    "success": True,
                    "hostname": host,
                    "ip_address": ip_address,
                    "explanation": f"Hostname {host} resolves to IP {ip_address}"
                }
                
                # Now do reverse lookup of the resolved IP
                try:
                    reverse_hostname = socket.gethostbyaddr(ip_address)[0]
                    results["reverse_lookup"] = {
                        "success": True,
                        "ip_address": ip_address,
                        "hostname": reverse_hostname,
                        "explanation": f"IP {ip_address} resolves to hostname {reverse_hostname}",
                        "consistency_check": reverse_hostname.lower() == host.lower()
                    }
                    if reverse_hostname.lower() != host.lower():
                        results["reverse_lookup"]["note"] = f"Reverse lookup returned different hostname ({reverse_hostname}) than original ({host})"
                except socket.gaierror:
                    results["reverse_lookup"] = {
                        "success": False,
                        "ip_address": ip_address,
                        "error": "Could not perform reverse lookup"
                    }
                    
            except socket.gaierror as e:
                results["forward_lookup"] = {
                    "success": False,
                    "hostname": host,
                    "error": f"Could not resolve hostname: {e}"
                }
                results["success"] = False
    
    except Exception as e:
        return {
            "success": False,
            "error": f"DNS lookup failed: {str(e)}",
            "error_type": "dns_lookup_failed"
        }
    
    # Format for backward compatibility with existing code expecting stdout/stderr format
    if results["success"]:
        summary_parts = []
        if results["forward_lookup"] and results["forward_lookup"]["success"]:
            fl = results["forward_lookup"]
            summary_parts.append(f"Forward: {fl['hostname']} → {fl['ip_address']}")
        if results["reverse_lookup"] and results["reverse_lookup"]["success"]:
            rl = results["reverse_lookup"]
            summary_parts.append(f"Reverse: {rl['ip_address']} → {rl['hostname']}")
        
        results["stdout"] = "; ".join(summary_parts) if summary_parts else "DNS lookup completed"
        results["stderr"] = ""
        results["exit_code"] = 0
    else:
        error_parts = []
        if results["forward_lookup"] and not results["forward_lookup"]["success"]:
            error_parts.append(results["forward_lookup"]["error"])
        if results["reverse_lookup"] and not results["reverse_lookup"]["success"]:
            error_parts.append(results["reverse_lookup"]["error"])
        
        results["stdout"] = ""
        results["stderr"] = "; ".join(error_parts) if error_parts else "DNS lookup failed"
        results["exit_code"] = 1
    
    return results

def run_nmap_scan(target: str, top_ports: int = 10) -> dict:
    """
    Performs a network port scan using Nmap to discover open services.
    
    Args:
        target (str): The IP address, hostname, or subnet to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        top_ports (int): Number of most common ports to scan (default: 10, max recommended: 1000)

    Returns:
        dict: Contains scan results
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(target)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    # Validate top_ports parameter
    is_valid_port, port_error, port_suggestion = validate_port(top_ports)
    if not is_valid_port:
        return {"success": False, "error": port_error}
    
    # Additional validation for port count range
    if top_ports > 1000:
        return {"success": False, "error": "Port count too high (max 1000)"}
    
    print(f"Scanning {target} for open ports (top {top_ports} most common ports)...")
    
    try:
        cmd = [
            "nmap",
            "-T4",  # Timing template: T4 = aggressive (faster but more detectable)
            "--top-ports", str(top_ports),
            "-oX", "-",  # Output as XML to stdout for easier parsing
            target
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Parse the XML output
        root = ET.fromstring(result.stdout)
        
        parsed_output = []
        host_info = {}
        
        # Extract host information
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None:
                host_info['status'] = status.get('state')
                
                # Get host address
                address = host.find('address')
                if address is not None:
                    host_info['ip'] = address.get('addr')
                
                # Get hostname if available
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_info['hostname'] = hostname.get('name')
                
                if status.get('state') == 'up':
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            state = port.find('state')
                            if state is not None:
                                port_id = port.get('portid')
                                protocol = port.get('protocol')
                                port_state = state.get('state')
                                
                                service = port.find('service')
                                service_name = service.get('name') if service is not None else 'unknown'
                                service_product = service.get('product') if service is not None else None
                                service_version = service.get('version') if service is not None else None
                                
                                # Build service description
                                service_desc = service_name
                                if service_product:
                                    service_desc += f" ({service_product}"
                                    if service_version:
                                        service_desc += f" {service_version}"
                                    service_desc += ")"
                                
                                port_info = {
                                    'port': port_id,
                                    'protocol': protocol,
                                    'state': port_state,
                                    'service': service_desc,
                                    'security_risk': _assess_port_security_risk(port_id, port_state, service_name),
                                    'recommendations': _get_port_security_recommendations(port_id, service_name)
                                }
                                parsed_output.append(port_info)

        # Prepare results
        results = {
            "success": True,
            "host_info": host_info,
            "ports_scanned": top_ports,
            "ports_found": parsed_output
        }

        if not parsed_output:
            results["output"] = f"No open or filtered ports found among the top {top_ports} ports on {target}."
        else:
            results["output"] = parsed_output

        return results
        
    except subprocess.CalledProcessError as e:
        # Nmap exits with an error if the host is down
        if "Host seems down" in (e.stderr or ""):
            return {
                "success": True, 
                "output": f"Host {target} appears to be down or not responding to ping."
            }
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "nmap_failed"
        }
    except ET.ParseError:
        return {
            "success": False, 
            "error": "Failed to parse nmap XML output.",
            "error_type": "parse_error"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Nmap command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }

def _assess_port_security_risk(port: str, state: str, service: str) -> str:
    """Assess the security risk level of an open port."""
    if state != 'open':
        return 'low'
    
    high_risk_ports = ['23', '21', '135', '139', '445', '1433', '3389', '5432', '3306']
    medium_risk_ports = ['22', '25', '53', '110', '143', '993', '995']
    
    if port in high_risk_ports:
        return 'high'
    elif port in medium_risk_ports:
        return 'medium'
    elif service in ['telnet', 'ftp', 'rlogin', 'rsh']:
        return 'high'
    else:
        return 'low'

def _get_port_security_recommendations(port: str, service: str) -> list:
    """Get security recommendations for specific ports/services."""
    recommendations = {
        '22': ['Use key-based authentication', 'Disable root login', 'Change default port', 'Use fail2ban'],
        '23': ['Replace with SSH immediately', 'Telnet sends passwords in plain text'],
        '21': ['Use SFTP/SCP instead', 'If needed, use FTPS with encryption'],
        '25': ['Ensure not an open relay', 'Use authentication for sending'],
        '53': ['Restrict to authorized networks only', 'Keep DNS software updated'],
        '80': ['Redirect to HTTPS', 'Keep web server updated'],
        '443': ['Use strong SSL/TLS configuration', 'Keep certificates updated'],
        '3389': ['Use Network Level Authentication', 'Restrict access by IP', 'Use strong passwords'],
        '3306': ['Never expose to internet', 'Use strong passwords', 'Keep MySQL updated'],
        '5432': ['Never expose to internet', 'Use strong passwords', 'Keep PostgreSQL updated']
    }
    
    return recommendations.get(port, ['Keep service updated', 'Use strong authentication', 'Monitor access logs'])

def run_netstat() -> dict:
    """
    Runs 'netstat -tulpn' to list listening TCP and UDP ports.

    Returns:
        dict: A dictionary with the command's output or an error message.
    """
    try:
        cmd = ["netstat", "-tulpn"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        return {
            "success": True, 
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Netstat operation timed out after 30 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "netstat_failed"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Netstat command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }
