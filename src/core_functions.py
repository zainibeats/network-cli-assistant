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
import logging
from .utils import (
    validate_ip, validate_ip_with_details, validate_hostname, validate_target, validate_port,
    create_validation_error, handle_network_timeout, handle_dns_resolution_error,
    handle_connection_refused_error, handle_permission_denied_error, handle_command_not_found_error,
    validate_network_operation_input, retry_network_operation
)
from .logging_config import log_operation, get_logger

@log_operation("ssh_command")
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
    is_valid_host, error_msg, _ = validate_target(host)
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
    logger = logging.getLogger("network_cli.ssh")
    logger.info(f"Executing SSH command on {host}", extra={
        "command": cmd,
        "host": host,
        "placeholder": True
    })
    
    print(f"(Placeholder) Executing '{cmd}' on host '{host}' via SSH...")
    
    result = {
        "success": True,
        "stdout": f"Placeholder output for '{cmd}' on {host}",
        "stderr": "",
        "exit_code": 0
    }
    
    # Log the command execution result
    get_logger().log_command_execution(cmd, host, result)
    
    return result

@log_operation("acl_generation")
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
    is_valid_src, src_error, _ = validate_ip_with_details(src_ip)
    if not is_valid_src:
        return {"success": False, "error": src_error}
    
    # Validate destination IP address
    is_valid_dst, dst_error, _ = validate_ip_with_details(dst_ip)
    if not is_valid_dst:
        return {"success": False, "error": dst_error}
    
    # Validate action parameter
    if not action or action not in ["permit", "deny"]:
        return {"success": False, "error": "Action must be either 'permit' or 'deny'"}

    logger = logging.getLogger("network_cli.acl")
    logger.info(f"Generating ACL rule", extra={
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "action": action
    })
    
    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    
    logger.info(f"ACL rule generated successfully", extra={
        "acl_rule": acl_rule
    })
    
    return {"success": True, "output": acl_rule}

@log_operation("ping")
def ping(host: str) -> dict:
    """
    Pings a host to test network connectivity and measure response times.
    
    Args:
        host: The hostname or IP address to ping
        
    Returns:
        dict: Contains success status and ping output
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    logger = logging.getLogger("network_cli.ping")
    logger.info(f"Starting ping operation to {host}")
    
    print(f"Pinging host '{host}'...")
    command = ['ping', '-c', '4', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        
        logger.info(f"Ping completed successfully", extra={
            "packets_sent": 4,
            "exit_code": result.returncode
        })
        
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Ping operation timed out after 30 seconds")
        return {
            "success": False,
            "error": f"Ping operation timed out after 30 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            logger.error(f"DNS resolution failed for {host}")
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            logger.error(f"Network unreachable when trying to ping {host}")
            return {
                "success": False,
                "error": f"Network unreachable when trying to ping {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            logger.error(f"Permission denied for ping operation")
            return {
                "success": False,
                "error": "Permission denied for ping operation",
                "error_type": "permission_denied"
            }
        else:
            logger.error(f"Ping failed: {stderr_output}")
            return {
                "success": False,
                "error": stderr_output or f"Failed to ping {host}",
                "error_type": "ping_failed"
            }
    except FileNotFoundError:
        logger.error("Ping command not found on system")
        return {
            "success": False,
            "error": "Ping command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        logger.error(f"Unexpected error during ping: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Unexpected error during ping: {str(e)}",
            "error_type": "unexpected_error"
        }

@log_operation("traceroute")
def traceroute(host: str) -> dict:
    """
    Traces the network path to a destination, showing each router (hop) along the way.
    
    Args:
        host: The hostname or IP address to trace the route to
        
    Returns:
        dict: Contains success status and traceroute output
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    logger = logging.getLogger("network_cli.traceroute")
    logger.info(f"Starting traceroute to {host}")
    
    print(f"Tracing network path to '{host}'...")
    command = ['traceroute', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        
        logger.info(f"Traceroute completed successfully", extra={
            "exit_code": result.returncode
        })
        
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Traceroute operation timed out after 120 seconds")
        return {
            "success": False,
            "error": f"Traceroute operation timed out after 120 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            logger.error(f"DNS resolution failed for {host}")
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            logger.error(f"Network unreachable when trying to traceroute to {host}")
            return {
                "success": False,
                "error": f"Network unreachable when trying to traceroute to {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            logger.error(f"Permission denied for traceroute operation")
            return {
                "success": False,
                "error": "Permission denied for traceroute operation",
                "error_type": "permission_denied"
            }
        else:
            logger.error(f"Traceroute failed: {stderr_output}")
            return {
                "success": False,
                "error": stderr_output or f"Failed to trace route to {host}",
                "error_type": "traceroute_failed"
            }
    except FileNotFoundError:
        logger.error("Traceroute command not found on system")
        return {
            "success": False,
            "error": "Traceroute command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        logger.error(f"Unexpected error during traceroute: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Unexpected error during traceroute: {str(e)}",
            "error_type": "unexpected_error"
        }

@log_operation("dns_lookup")
def dns_lookup(host: str) -> dict:
    """
    Performs comprehensive DNS lookups including forward and reverse resolution.
    
    Args:
        host: The hostname or IP address to look up
        
    Returns:
        dict: Contains forward/reverse lookup results
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    logger = logging.getLogger("network_cli.dns")
    logger.info(f"Starting DNS lookup for {host}")
    
    print(f"Performing DNS lookup for '{host}'...")
    
    results = {
        "success": True,
        "forward_lookup": None,
        "reverse_lookup": None
    }
    
    # Determine if input is an IP address or hostname
    is_ip_address = validate_ip(host)
    logger.debug(f"Input type detected: {'IP address' if is_ip_address else 'hostname'}")
    
    try:
        if is_ip_address:
            # Input is IP address - do reverse lookup first, then forward lookup of result
            print(f"Input detected as IP address, performing reverse lookup...")
            try:
                hostname = socket.gethostbyaddr(host)[0]
                logger.info(f"Reverse lookup successful: {host} -> {hostname}")
                results["reverse_lookup"] = {
                    "success": True,
                    "ip_address": host,
                    "hostname": hostname
                }
                
                # Now do forward lookup of the resolved hostname
                try:
                    forward_ip = socket.gethostbyname(hostname)
                    logger.info(f"Forward lookup successful: {hostname} -> {forward_ip}")
                    results["forward_lookup"] = {
                        "success": True,
                        "hostname": hostname,
                        "ip_address": forward_ip,
                        "consistency_check": forward_ip == host
                    }
                    if forward_ip != host:
                        logger.warning(f"DNS consistency issue: forward lookup returned {forward_ip}, original was {host}")
                        results["forward_lookup"]["warning"] = f"Forward lookup returned different IP ({forward_ip}) than original ({host})"
                except socket.gaierror:
                    logger.warning(f"Forward lookup failed for resolved hostname {hostname}")
                    results["forward_lookup"] = {
                        "success": False,
                        "error": f"Could not perform forward lookup for resolved hostname {hostname}"
                    }
                    
            except (socket.gaierror, socket.herror) as e:
                logger.error(f"Reverse lookup failed for {host}: {e}")
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
                logger.info(f"Forward lookup successful: {host} -> {ip_address}")
                results["forward_lookup"] = {
                    "success": True,
                    "hostname": host,
                    "ip_address": ip_address
                }
                
                # Now do reverse lookup of the resolved IP
                try:
                    reverse_hostname = socket.gethostbyaddr(ip_address)[0]
                    logger.info(f"Reverse lookup successful: {ip_address} -> {reverse_hostname}")
                    results["reverse_lookup"] = {
                        "success": True,
                        "ip_address": ip_address,
                        "hostname": reverse_hostname,
                        "consistency_check": reverse_hostname.lower() == host.lower()
                    }
                    if reverse_hostname.lower() != host.lower():
                        logger.warning(f"DNS consistency issue: reverse lookup returned {reverse_hostname}, original was {host}")
                        results["reverse_lookup"]["note"] = f"Reverse lookup returned different hostname ({reverse_hostname}) than original ({host})"
                except (socket.gaierror, socket.herror):
                    logger.warning(f"Reverse lookup failed for {ip_address}")
                    results["reverse_lookup"] = {
                        "success": False,
                        "ip_address": ip_address,
                        "error": "Could not perform reverse lookup"
                    }
                    
            except socket.gaierror as e:
                logger.error(f"Forward lookup failed for {host}: {e}")
                results["forward_lookup"] = {
                    "success": False,
                    "hostname": host,
                    "error": f"Could not resolve hostname: {e}"
                }
                results["success"] = False
    
    except Exception as e:
        logger.error(f"DNS lookup failed: {str(e)}", exc_info=True)
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

@log_operation("host_discovery")
def discover_hosts(network: str) -> dict:
    """
    Discovers active hosts on a network using a more targeted approach.
    
    Args:
        network (str): The network range to scan in CIDR notation (e.g., 192.168.1.0/24)
        
    Returns:
        dict: Contains list of active hosts found on the network
    """
    # Import the new validation function
    from .utils import validate_network_target
    
    # Validate network parameter (supports CIDR notation)
    is_valid_network, error_msg, target_type = validate_network_target(network)
    if not is_valid_network:
        return {"success": False, "error": error_msg}
    
    # Ensure it's actually a network range, not a single host
    if target_type != 'cidr':
        return {"success": False, "error": "Host discovery requires a network range in CIDR notation (e.g., 192.168.1.0/24)"}
    
    logger = logging.getLogger("network_cli.host_discovery")
    logger.info(f"Starting host discovery on {network}")
    
    print(f"Discovering active hosts on network {network}...")
    
    # Note: In Docker environments, standard ping sweeps report all IPs as up due to bridge networking
    # We'll provide a more realistic demonstration by limiting results and explaining the limitation
    try:
        # For demonstration in Docker environment, we'll simulate a more realistic scan
        # by checking for actual services on a subset of IPs
        import ipaddress
        
        network_obj = ipaddress.ip_network(network, strict=False)
        
        # In a real environment, this would be a proper nmap scan
        # For Docker demo, we'll simulate finding a few active hosts
        active_hosts = []
        
        # Check a sample of IPs for actual responsiveness (first 10 IPs)
        sample_ips = list(network_obj.hosts())[:10]  # First 10 host IPs
        
        for ip in sample_ips:
            # Quick port check to see if host is actually responsive
            cmd = [
                "nmap",
                "-sS",  # SYN scan
                "-T4",  # Fast timing
                "--top-ports", "1",  # Just check most common port
                "-oG", "-",  # Greppable output
                str(ip)
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=5)
                
                # Parse greppable output
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Host:') and 'Status: Up' in line:
                        active_hosts.append(str(ip))
                        break
                        
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Host didn't respond or scan failed
                continue
        
        # Remove duplicates while preserving order
        unique_hosts = []
        seen = set()
        for host in active_hosts:
            if host not in seen:
                unique_hosts.append(host)
                seen.add(host)
        
        logger.info(f"Host discovery completed: found {len(unique_hosts)} active hosts")
        
        results = {
            "success": True,
            "network": network,
            "active_hosts": unique_hosts,
            "total_hosts_found": len(unique_hosts),
            "scan_type": "host_discovery"
        }
        
        if unique_hosts:
            results["output"] = f"Found {len(unique_hosts)} active hosts on {network}:\n" + "\n".join(f"  • {host}" for host in unique_hosts)
            results["output"] += f"\n\nNote: Scanned first 10 IPs in range. In Docker environments, network discovery may show different results than physical networks."
        else:
            results["output"] = f"No active hosts found in sample scan of {network}. Network may be down or heavily firewalled.\n\nNote: In Docker environments, standard ping sweeps may not work as expected due to bridge networking."
        
        # Log the scan result
        get_logger().log_network_scan(network, "host_discovery", results)
        
        return results
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Host discovery failed: {e.stderr or str(e)}")
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "nmap_failed"
        }
    except FileNotFoundError:
        logger.error("Nmap command not found on system")
        return {
            "success": False,
            "error": "Nmap command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        logger.error(f"Unexpected error during host discovery: {str(ex)}", exc_info=True)
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }

@log_operation("nmap_scan")
def run_nmap_scan(target: str, top_ports: int = 10) -> dict:
    """
    Performs a network port scan using Nmap to discover open services.
    
    Args:
        target (str): The IP address, hostname, or subnet to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        top_ports (int): Number of most common ports to scan (default: 10, max recommended: 1000)

    Returns:
        dict: Contains scan results
    """
    # Import the new validation function
    from .utils import validate_network_target
    
    # Validate target parameter (supports CIDR notation)
    is_valid_target, error_msg, target_type = validate_network_target(target)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    # Validate top_ports parameter
    is_valid_port, port_error, _ = validate_port(top_ports)
    if not is_valid_port:
        return {"success": False, "error": port_error}
    
    # Additional validation for port count range
    if top_ports > 1000:
        return {"success": False, "error": "Port count too high (max 1000)"}
    
    logger = logging.getLogger("network_cli.nmap")
    logger.info(f"Starting nmap scan of {target}", extra={
        "target": target,
        "top_ports": top_ports
    })
    
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
        all_hosts = []
        hosts_with_ports = []
        
        # Extract information for all hosts
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                host_info = {'status': status.get('state')}
                
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
                
                all_hosts.append(host_info)
                
                # Check for open ports on this host
                ports = host.find('ports')
                host_ports = []
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
                                'host_ip': host_info['ip'],
                                'port': port_id,
                                'protocol': protocol,
                                'state': port_state,
                                'service': service_desc,
                                'security_risk': _assess_port_security_risk(port_id, port_state, service_name),
                                'recommendations': _get_port_security_recommendations(port_id, service_name)
                            }
                            parsed_output.append(port_info)
                            host_ports.append(port_info)
                
                # If this host has open ports, add it to the list
                if host_ports:
                    host_with_ports = host_info.copy()
                    host_with_ports['open_ports'] = host_ports
                    hosts_with_ports.append(host_with_ports)

        # Prepare results
        results = {
            "success": True,
            "target": target,
            "ports_scanned": top_ports,
            "ports_found": parsed_output,
            "hosts_scanned": len(all_hosts),
            "hosts_with_ports": hosts_with_ports,
            # Keep host_info for backward compatibility (use first host if available)
            "host_info": all_hosts[0] if all_hosts else {}
        }

        if not parsed_output:
            logger.info(f"No open ports found on {target}")
            if len(all_hosts) > 1:
                results["output"] = f"Scanned {len(all_hosts)} hosts on {target}. No open ports found among the top {top_ports} ports."
            else:
                results["output"] = f"No open or filtered ports found among the top {top_ports} ports on {target}."
            results["interpretation"] = {
                "overall_risk": "minimal",
                "summary": f"No open ports detected on {target} - systems appear well secured or may be down",
                "recommendations": ["Verify targets are reachable", "Systems may have strong firewall protection"]
            }
        else:
            open_ports = [p for p in parsed_output if p.get("state") == "open"]
            logger.info(f"Nmap scan completed: found {len(open_ports)} open ports on {len(hosts_with_ports)} hosts", extra={
                "open_ports": [f"{p.get('host_ip')}:{p.get('port')}" for p in open_ports],
                "total_ports_scanned": top_ports,
                "hosts_with_ports": len(hosts_with_ports)
            })
            
            # For network scans with multiple hosts, add summary info but keep the parsed_output for the formatter
            if len(hosts_with_ports) > 1:
                results["network_summary"] = f"Found open ports on {len(hosts_with_ports)} hosts:\n\n"
                for host_data in hosts_with_ports:
                    host_ip = host_data['ip']
                    host_ports = [p for p in host_data['open_ports'] if p['state'] == 'open']
                    if host_ports:  # Only show hosts that actually have open ports
                        results["network_summary"] += f"Host {host_ip}:\n"
                        for port in host_ports:
                            results["network_summary"] += f"  • Port {port['port']} ({port['service']}) - {port['security_risk'].upper()} RISK\n"
                        results["network_summary"] += "\n"
                # Keep parsed_output for the special nmap formatter
                results["output"] = parsed_output
            else:
                results["output"] = parsed_output
            
            # Add comprehensive result interpretation
            results["interpretation"] = _interpret_nmap_results(results)

        # Log the scan result
        get_logger().log_network_scan(target, "nmap", results)
        
        return results
        
    except subprocess.CalledProcessError as e:
        # Nmap exits with an error if the host is down
        if "Host seems down" in (e.stderr or ""):
            logger.warning(f"Host {target} appears to be down")
            return {
                "success": True, 
                "output": f"Host {target} appears to be down or not responding to ping."
            }
        logger.error(f"Nmap scan failed: {e.stderr or str(e)}")
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "nmap_failed"
        }
    except ET.ParseError:
        logger.error("Failed to parse nmap XML output")
        return {
            "success": False, 
            "error": "Failed to parse nmap XML output.",
            "error_type": "parse_error"
        }
    except FileNotFoundError:
        logger.error("Nmap command not found on system")
        return {
            "success": False,
            "error": "Nmap command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        logger.error(f"Unexpected error during nmap scan: {str(ex)}", exc_info=True)
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }

def _assess_port_security_risk(port: str, state: str, service: str) -> str:
    """Assess the security risk level of an open port."""
    if state != 'open':
        return 'low'
    
    # Critical risk ports - immediate security concern
    critical_risk_ports = ['23', '135', '139', '445', '1433', '3306', '5432']
    # High risk ports - require careful configuration
    high_risk_ports = ['21', '25', '53', '3389', '5900', '5901', '6379', '27017']
    # Medium risk ports - common services that need monitoring
    medium_risk_ports = ['22', '80', '110', '143', '993', '995', '8080', '8443']
    
    if port in critical_risk_ports:
        return 'critical'
    elif port in high_risk_ports:
        return 'high'
    elif port in medium_risk_ports:
        return 'medium'
    elif service in ['telnet', 'ftp', 'rlogin', 'rsh', 'netbios-ssn', 'microsoft-ds']:
        return 'critical'
    elif service in ['vnc', 'redis', 'mongodb', 'mysql', 'postgresql']:
        return 'high'
    else:
        return 'low'

def _get_port_security_recommendations(port: str, service: str) -> list:
    """Get security recommendations for specific ports/services."""
    recommendations = {
        '21': ['Replace with SFTP/SCP', 'If FTP needed, use FTPS with encryption', 'Disable anonymous access'],
        '22': ['Use key-based authentication', 'Disable root login', 'Change default port', 'Use fail2ban', 'Limit user access'],
        '23': ['CRITICAL: Replace with SSH immediately', 'Telnet transmits passwords in plain text', 'Disable telnet service'],
        '25': ['Ensure not an open relay', 'Use SMTP authentication', 'Enable TLS encryption', 'Monitor for spam'],
        '53': ['Restrict to authorized networks only', 'Disable recursion for public servers', 'Keep DNS software updated', 'Monitor for DNS amplification attacks'],
        '80': ['Redirect all traffic to HTTPS', 'Keep web server updated', 'Use security headers', 'Regular security scans'],
        '110': ['Use POP3S (port 995) instead', 'Disable plain text authentication', 'Consider IMAP as alternative'],
        '135': ['CRITICAL: Block at firewall', 'Windows RPC endpoint mapper', 'High risk for exploitation', 'Disable if not needed'],
        '139': ['CRITICAL: Block at firewall', 'NetBIOS session service', 'Legacy protocol with security issues', 'Use SMB over port 445 instead'],
        '143': ['Use IMAPS (port 993) instead', 'Disable plain text authentication', 'Enable TLS encryption'],
        '443': ['Use strong SSL/TLS configuration', 'Keep certificates updated', 'Disable weak ciphers', 'Enable HSTS'],
        '445': ['CRITICAL: Restrict access', 'SMB file sharing', 'Vulnerable to ransomware', 'Use VPN for remote access'],
        '993': ['Verify certificate validity', 'Use strong authentication', 'Monitor for brute force attacks'],
        '995': ['Verify certificate validity', 'Use strong authentication', 'Monitor for brute force attacks'],
        '1433': ['CRITICAL: Never expose to internet', 'SQL Server default port', 'Use strong passwords', 'Enable encryption', 'Change default port'],
        '3306': ['CRITICAL: Never expose to internet', 'MySQL default port', 'Use strong passwords', 'Enable SSL', 'Change default port'],
        '3389': ['Use Network Level Authentication', 'Restrict access by IP', 'Use strong passwords', 'Enable account lockout', 'Consider VPN access'],
        '5432': ['CRITICAL: Never expose to internet', 'PostgreSQL default port', 'Use strong passwords', 'Enable SSL', 'Change default port'],
        '5900': ['Use VNC over SSH tunnel', 'Change default password', 'Restrict network access', 'Consider more secure alternatives'],
        '5901': ['Use VNC over SSH tunnel', 'Change default password', 'Restrict network access', 'Consider more secure alternatives'],
        '6379': ['CRITICAL: Never expose to internet', 'Redis default port', 'Enable authentication', 'Use SSL/TLS', 'Bind to localhost only'],
        '8080': ['Use HTTPS (8443) instead', 'Often used for web applications', 'Implement proper authentication', 'Regular security updates'],
        '8443': ['Verify SSL/TLS configuration', 'Keep certificates updated', 'Monitor for vulnerabilities'],
        '27017': ['CRITICAL: Never expose to internet', 'MongoDB default port', 'Enable authentication', 'Use SSL/TLS', 'Bind to localhost only']
    }
    
    return recommendations.get(port, ['Keep service updated', 'Use strong authentication', 'Monitor access logs', 'Restrict network access'])

def _interpret_nmap_results(scan_results: dict) -> dict:
    """
    Interpret nmap scan results and provide comprehensive security analysis.
    
    Args:
        scan_results: The results from run_nmap_scan function
        
    Returns:
        dict: Comprehensive analysis with security implications and recommendations
    """
    if not scan_results.get("success"):
        return {
            "overall_risk": "unknown",
            "summary": "Scan failed",
            "recommendations": ["Verify target is reachable", "Check firewall settings", "Ensure nmap has proper permissions"]
        }
    
    if not scan_results.get("ports_found"):
        return {
            "overall_risk": "minimal",
            "summary": "No open ports found - system appears well secured",
            "recommendations": ["Verify target is reachable", "System may have strong firewall protection"]
        }
    
    ports_found = scan_results["ports_found"]
    host_info = scan_results.get("host_info", {})
    
    # Analyze risk levels
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    critical_services = []
    high_risk_services = []
    open_ports = []
    
    for port_info in ports_found:
        if port_info["state"] == "open":
            open_ports.append(port_info["port"])
            risk_level = port_info["security_risk"]
            risk_counts[risk_level] += 1
            
            if risk_level == "critical":
                critical_services.append(f"Port {port_info['port']} ({port_info['service']})")
            elif risk_level == "high":
                high_risk_services.append(f"Port {port_info['port']} ({port_info['service']})")
    
    # Determine overall risk
    if risk_counts["critical"] > 0:
        overall_risk = "critical"
    elif risk_counts["high"] > 0:
        overall_risk = "high"
    elif risk_counts["medium"] > 0:
        overall_risk = "medium"
    elif risk_counts["low"] > 0:
        overall_risk = "low"
    else:
        overall_risk = "minimal"
    
    # Generate summary
    total_open = len(open_ports)
    target = host_info.get("ip", "target")
    
    summary_parts = [
        f"Scanned {target} and found {total_open} open port{'s' if total_open != 1 else ''}"
    ]
    
    if risk_counts["critical"] > 0:
        summary_parts.append(f"{risk_counts['critical']} CRITICAL risk service{'s' if risk_counts['critical'] != 1 else ''}")
    if risk_counts["high"] > 0:
        summary_parts.append(f"{risk_counts['high']} high risk service{'s' if risk_counts['high'] != 1 else ''}")
    if risk_counts["medium"] > 0:
        summary_parts.append(f"{risk_counts['medium']} medium risk service{'s' if risk_counts['medium'] != 1 else ''}")
    
    summary = ". ".join(summary_parts) + "."
    
    # Generate recommendations
    recommendations = []
    
    if critical_services:
        recommendations.append("IMMEDIATE ACTION REQUIRED:")
        for service in critical_services:
            recommendations.append(f"  • {service} - Extremely high security risk")
        recommendations.append("  • Block these services at firewall level immediately")
        recommendations.append("  • Review if these services are actually needed")
    
    if high_risk_services:
        recommendations.append("HIGH PRIORITY:")
        for service in high_risk_services:
            recommendations.append(f"  • {service} - Requires immediate security review")
        recommendations.append("  • Implement strong authentication and encryption")
        recommendations.append("  • Restrict access to authorized networks only")
    
    # General recommendations based on findings
    if total_open > 10:
        recommendations.append("GENERAL: Large number of open ports detected - review if all services are necessary")
    
    if any(port in ["22", "3389"] for port in open_ports):
        recommendations.append("REMOTE ACCESS: SSH/RDP detected - ensure strong authentication is enabled")
    
    if any(port in ["80", "443", "8080", "8443"] for port in open_ports):
        recommendations.append("WEB SERVICES: Web servers detected - ensure they are properly secured and updated")
    
    if any(port in ["1433", "3306", "5432", "6379", "27017"] for port in open_ports):
        recommendations.append("DATABASES: Database services exposed - these should NEVER be accessible from internet")
    
    # Add follow-up suggestions
    recommendations.extend([
        "NEXT STEPS:",
        "  • Run detailed vulnerability scan with nmap scripts (-sC -sV)",
        "  • Check for default credentials on discovered services",
        "  • Review firewall rules and network segmentation",
        "  • Monitor these services for suspicious activity"
    ])
    
    return {
        "overall_risk": overall_risk,
        "summary": summary,
        "risk_breakdown": risk_counts,
        "critical_services": critical_services,
        "high_risk_services": high_risk_services,
        "total_open_ports": total_open,
        "recommendations": recommendations,
        "target_info": host_info
    }

@log_operation("netstat")
def run_netstat() -> dict:
    """
    Runs 'netstat -tulpn' to list listening TCP and UDP ports.

    Returns:
        dict: A dictionary with the command's output or an error message.
    """
    logger = logging.getLogger("network_cli.netstat")
    logger.info("Starting netstat operation")
    
    try:
        cmd = ["netstat", "-tulpn"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        
        logger.info("Netstat completed successfully", extra={
            "exit_code": result.returncode
        })
        
        return {
            "success": True, 
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        logger.error("Netstat operation timed out after 30 seconds")
        return {
            "success": False,
            "error": "Netstat operation timed out after 30 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"Netstat failed: {e.stderr or str(e)}")
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "netstat_failed"
        }
    except FileNotFoundError:
        logger.error("Netstat command not found on system")
        return {
            "success": False,
            "error": "Netstat command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        logger.error(f"Unexpected error during netstat: {str(ex)}", exc_info=True)
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }
