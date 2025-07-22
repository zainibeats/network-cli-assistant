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
        return create_validation_error("target host", host, error_msg, suggestion)
    
    # Validate command parameter
    if not cmd or not isinstance(cmd, str):
        return create_validation_error("command", str(cmd), "Command cannot be empty", "Please provide a valid shell command")
    
    cmd = cmd.strip()
    if not cmd:
        return create_validation_error("command", cmd, "Command cannot be empty", "Please provide a valid shell command")
    
    # Basic command sanitization - prevent obvious injection attempts
    dangerous_patterns = [';', '&&', '||', '|', '>', '>>', '<', '`', '$()']
    if any(pattern in cmd for pattern in dangerous_patterns):
        return {
            "success": False,
            "error": "Command contains potentially dangerous characters",
            "security_note": "For security reasons, commands with shell operators are not allowed",
            "suggestion": "Use simple commands without pipes, redirects, or command chaining"
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
        return create_validation_error("source IP address", src_ip, src_error, src_suggestion)
    
    # Validate destination IP address
    is_valid_dst, dst_error, dst_suggestion = validate_ip_with_details(dst_ip)
    if not is_valid_dst:
        return create_validation_error("destination IP address", dst_ip, dst_error, dst_suggestion)
    
    # Validate action parameter
    if not action or action not in ["permit", "deny"]:
        return create_validation_error("action", str(action), "Action must be either 'permit' or 'deny'", "Use 'permit' to allow traffic or 'deny' to block traffic")

    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    return {"success": True, "output": acl_rule}

def ping(host: str) -> dict:
    """
    Pings a host to test network connectivity and measure response times.
    
    This function sends ICMP Echo Request packets to test:
    - Network reachability (can packets reach the destination?)
    - Round-Trip Time (RTT) - how long packets take to travel there and back
    - Packet loss - what percentage of packets are lost in transit
    
    Args:
        host: The hostname or IP address to ping
        
    Returns:
        dict: Contains success status, ping output with RTT analysis, and educational context
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return create_validation_error("target", host, error_msg, suggestion)

    print(f"Pinging host '{host}' to test network connectivity...")
    command = ['ping', '-c', '4', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        
        # Add educational context to the output
        enhanced_output = {
            "success": True,
            "output": result.stdout,
            "educational_context": {
                "what_is_ping": "Ping uses ICMP (Internet Control Message Protocol) to test network connectivity",
                "rtt_meaning": "RTT (Round-Trip Time) measures how long it takes for a packet to travel to the destination and back",
                "packet_loss_meaning": "Packet loss indicates network congestion, hardware issues, or connectivity problems",
                "interpretation_guide": {
                    "excellent_rtt": "< 10ms - Local network or very fast connection",
                    "good_rtt": "10-50ms - Good internet connection",
                    "acceptable_rtt": "50-100ms - Acceptable for most applications",
                    "poor_rtt": "> 100ms - May cause noticeable delays",
                    "packet_loss_0": "0% loss - Perfect connectivity",
                    "packet_loss_low": "1-5% loss - Minor network issues",
                    "packet_loss_high": "> 5% loss - Significant network problems"
                }
            }
        }
        return enhanced_output
        
    except subprocess.TimeoutExpired:
        return handle_network_timeout("Ping", host, 30)
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        # Handle specific error cases with detailed guidance
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            return handle_dns_resolution_error(host, stderr_output)
        elif "Network is unreachable" in stderr_output:
            return {
                "success": False,
                "error": f"Network unreachable when trying to ping {host}",
                "error_type": "network_unreachable",
                "troubleshooting": {
                    "possible_causes": [
                        "No route to destination network",
                        "Network interface is down",
                        "Routing table misconfiguration",
                        "ISP or network provider issues"
                    ],
                    "suggested_actions": [
                        "Check your network connection",
                        "Verify your default gateway is reachable",
                        "Try pinging your local gateway first",
                        "Check routing table with 'route -n' or 'ip route'"
                    ]
                },
                "educational_note": "Network unreachable means your system cannot find a route to the destination network."
            }
        elif "Operation not permitted" in stderr_output:
            return handle_permission_denied_error("ping operation", "ICMP ping may require elevated privileges on some systems")
        else:
            return {
                "success": False,
                "error": stderr_output or f"Failed to ping {host}",
                "educational_note": "Ping failures can indicate: host is down, firewall blocking ICMP, network routing issues, or DNS resolution problems"
            }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Ping command not found",
            "troubleshooting": {
                "possible_causes": [
                    "Ping utility is not installed",
                    "Ping is not in the system PATH"
                ],
                "suggested_actions": [
                    "Install ping utility (usually part of iputils package)",
                    "Check if ping is available in /bin/ping or /usr/bin/ping"
                ]
            }
        }

def traceroute(host: str) -> dict:
    """
    Traces the network path to a destination, showing each router (hop) along the way.
    
    Traceroute reveals the route packets take through the internet by:
    - Sending packets with increasing TTL (Time To Live) values
    - Recording each router that responds when TTL expires
    - Measuring response times for each hop in the path
    
    This helps diagnose:
    - Network routing issues
    - Where packet loss occurs
    - Network latency sources
    - ISP and network infrastructure
    
    Args:
        host: The hostname or IP address to trace the route to
        
    Returns:
        dict: Contains success status, traceroute output, and educational context about network routing
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return create_validation_error("target", host, error_msg, suggestion)

    print(f"Tracing network path to '{host}' (this may take 30-60 seconds)...")
    command = ['traceroute', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        
        enhanced_output = {
            "success": True,
            "output": result.stdout,
            "educational_context": {
                "what_is_traceroute": "Traceroute maps the path packets take through the internet by revealing each router (hop) along the way",
                "how_it_works": "Uses TTL (Time To Live) field - starts with TTL=1, increases until destination is reached",
                "hop_explanation": "Each line represents a router/gateway that forwarded your packet toward the destination",
                "timing_meaning": "Three time measurements show round-trip time to each hop (usually in milliseconds)",
                "asterisk_meaning": "* indicates the router didn't respond (may be configured to not reply to traceroute)",
                "interpretation_guide": {
                    "first_hops": "Usually your local router/gateway and ISP equipment",
                    "middle_hops": "Internet backbone routers and intermediate networks",
                    "final_hops": "Destination network's routers and the target host",
                    "high_latency_hop": "Sudden latency increase may indicate network congestion or long-distance link",
                    "timeouts": "Multiple * in a row may indicate firewalls or routing issues"
                },
                "troubleshooting_tips": [
                    "Compare routes to different destinations to isolate problems",
                    "High latency at a specific hop indicates issues at that network",
                    "Packet loss at intermediate hops may not affect end-to-end connectivity",
                    "Geographic routing can be seen through hop hostnames and latencies"
                ]
            }
        }
        return enhanced_output
        
    except subprocess.TimeoutExpired:
        return handle_network_timeout("Traceroute", host, 120)
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        # Handle specific error cases with detailed guidance
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            return handle_dns_resolution_error(host, stderr_output)
        elif "Network is unreachable" in stderr_output:
            return {
                "success": False,
                "error": f"Network unreachable when trying to traceroute to {host}",
                "error_type": "network_unreachable",
                "troubleshooting": {
                    "possible_causes": [
                        "No route to destination network",
                        "Network interface is down",
                        "Routing table misconfiguration",
                        "ISP or network provider issues"
                    ],
                    "suggested_actions": [
                        "Check your network connection",
                        "Verify your default gateway is reachable",
                        "Try pinging the target first",
                        "Check routing table with 'route -n' or 'ip route'"
                    ]
                },
                "educational_note": "Network unreachable means your system cannot find a route to the destination network."
            }
        elif "Operation not permitted" in stderr_output:
            return handle_permission_denied_error("traceroute operation", "Traceroute may require elevated privileges on some systems")
        else:
            return {
                "success": False,
                "error": stderr_output or f"Failed to trace route to {host}",
                "educational_note": "Traceroute failures can occur due to: firewall blocking, network routing issues, or the traceroute command not being available"
            }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Traceroute command not found",
            "troubleshooting": {
                "possible_causes": [
                    "Traceroute utility is not installed",
                    "Traceroute is not in the system PATH"
                ],
                "suggested_actions": [
                    "Install traceroute utility (usually part of iputils package)",
                    "Try 'tracepath' as an alternative",
                    "Check if traceroute is available in /usr/bin/traceroute"
                ]
            }
        }

def dns_lookup(host: str) -> dict:
    """
    Performs comprehensive DNS lookups including forward and reverse resolution.
    
    DNS (Domain Name System) is the internet's phone book that translates:
    - Forward lookup: hostname → IP address (e.g., google.com → 142.250.191.14)
    - Reverse lookup: IP address → hostname (e.g., 142.250.191.14 → google.com)
    
    This function provides both lookups when possible to give complete DNS information.
    
    Args:
        host: The hostname or IP address to look up
        
    Returns:
        dict: Contains forward/reverse lookup results and educational context about DNS
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(host)
    if not is_valid_target:
        return create_validation_error("target", host, error_msg, suggestion)
    
    print(f"Performing comprehensive DNS lookup for '{host}'...")
    
    results = {
        "success": True,
        "forward_lookup": None,
        "reverse_lookup": None,
        "educational_context": {
            "what_is_dns": "DNS translates human-readable domain names to IP addresses and vice versa",
            "forward_lookup_explanation": "Forward lookup converts domain names (like google.com) to IP addresses",
            "reverse_lookup_explanation": "Reverse lookup converts IP addresses back to domain names (PTR records)",
            "dns_record_types": {
                "A_record": "Maps hostname to IPv4 address",
                "AAAA_record": "Maps hostname to IPv6 address", 
                "PTR_record": "Maps IP address back to hostname (reverse lookup)",
                "CNAME_record": "Creates an alias from one domain name to another",
                "MX_record": "Specifies mail servers for a domain"
            },
            "troubleshooting_tips": [
                "DNS propagation can take 24-48 hours for new records",
                "Try different DNS servers (8.8.8.8, 1.1.1.1) if resolution fails",
                "Check if domain has expired or DNS records are misconfigured",
                "Reverse lookups may fail if PTR records aren't configured"
            ]
        }
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
                    "error": f"Could not perform reverse lookup: {e}",
                    "explanation": "Reverse lookup failed - PTR record may not exist or be configured"
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
                        "error": "Could not perform reverse lookup - PTR record may not exist"
                    }
                    
            except socket.gaierror as e:
                results["forward_lookup"] = {
                    "success": False,
                    "hostname": host,
                    "error": f"Could not resolve hostname: {e}",
                    "explanation": "Forward lookup failed - domain may not exist or DNS server unreachable"
                }
                results["success"] = False
    
    except Exception as e:
        return {
            "success": False,
            "error": f"DNS lookup failed: {e}",
            "educational_note": "DNS lookup errors can indicate network connectivity issues, DNS server problems, or invalid hostnames/IP addresses"
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
    Performs a network port scan using Nmap to discover open services and potential security issues.
    
    Nmap (Network Mapper) is a security scanner that:
    - Discovers which ports are open on target systems
    - Identifies services running on those ports
    - Helps assess network security posture
    - Can detect potential vulnerabilities
    
    Port states explained:
    - Open: Service is actively accepting connections (potential entry point)
    - Closed: Port is accessible but no service is listening
    - Filtered: Port is blocked by firewall or packet filter
    
    Args:
        target (str): The IP address, hostname, or subnet to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        top_ports (int): Number of most common ports to scan (default: 10, max recommended: 1000)

    Returns:
        dict: Contains scan results with security analysis and educational context
    """
    # Validate target parameter
    is_valid_target, error_msg, suggestion = validate_target(target)
    if not is_valid_target:
        return create_validation_error("target", target, error_msg, suggestion)
    
    # Validate top_ports parameter
    is_valid_port, port_error, port_suggestion = validate_port(top_ports)
    if not is_valid_port:
        return create_validation_error("port count", str(top_ports), port_error, port_suggestion)
    
    # Additional validation for port count range
    if top_ports > 1000:
        return create_validation_error("port count", str(top_ports), "Port count too high (max 1000)", "Use a smaller number to avoid excessive scan time")
    
    print(f"Scanning {target} for open ports (top {top_ports} most common ports)...")
    print("Note: Port scanning should only be performed on systems you own or have permission to test.")
    
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

        # Prepare enhanced results with educational context
        enhanced_results = {
            "success": True,
            "host_info": host_info,
            "ports_scanned": top_ports,
            "ports_found": parsed_output,
            "educational_context": {
                "what_is_nmap": "Nmap is a network discovery and security auditing tool used to find open ports and services",
                "port_states_explained": {
                    "open": "Service is running and accepting connections - potential entry point for attackers",
                    "closed": "Port is reachable but no service is listening - generally safe",
                    "filtered": "Port is blocked by firewall - good security practice for unused services"
                },
                "security_implications": {
                    "open_ports": "Each open port represents a potential attack surface",
                    "service_versions": "Outdated service versions may contain known vulnerabilities",
                    "unnecessary_services": "Services not needed should be disabled to reduce attack surface",
                    "firewall_importance": "Firewalls should block unused ports (showing as 'filtered')"
                },
                "common_ports_reference": {
                    "22": "SSH - Secure remote access",
                    "23": "Telnet - Insecure remote access (avoid)",
                    "25": "SMTP - Email sending",
                    "53": "DNS - Domain name resolution",
                    "80": "HTTP - Web server (unencrypted)",
                    "443": "HTTPS - Secure web server",
                    "993": "IMAPS - Secure email access",
                    "3389": "RDP - Windows remote desktop"
                },
                "best_practices": [
                    "Only run necessary services",
                    "Keep services updated to latest versions",
                    "Use firewalls to block unused ports",
                    "Monitor for unexpected open ports",
                    "Use strong authentication for all services",
                    "Regular security audits and port scans"
                ]
            }
        }

        if not parsed_output:
            enhanced_results["output"] = f"No open or filtered ports found among the top {top_ports} ports on {target}."
            enhanced_results["security_assessment"] = "Good - No obvious entry points detected in common ports"
        else:
            enhanced_results["output"] = parsed_output
            # Assess overall security posture
            open_ports = [p for p in parsed_output if p['state'] == 'open']
            high_risk_ports = [p for p in open_ports if p['security_risk'] == 'high']
            
            if high_risk_ports:
                enhanced_results["security_assessment"] = f"Attention needed - {len(high_risk_ports)} high-risk open ports detected"
            elif open_ports:
                enhanced_results["security_assessment"] = f"Review recommended - {len(open_ports)} open ports found"
            else:
                enhanced_results["security_assessment"] = "Good - Only filtered ports detected"

        return enhanced_results
        
    except subprocess.CalledProcessError as e:
        # Nmap exits with an error if the host is down
        if "Host seems down" in e.stderr:
            return {
                "success": True, 
                "output": f"Host {target} appears to be down or not responding to ping.",
                "educational_note": "Host may be down, blocking ping (ICMP), or behind a firewall. Try scanning with -Pn flag to skip ping."
            }
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "educational_note": "Nmap scan failed. Ensure nmap is installed and you have permission to scan the target."
        }
    except ET.ParseError:
        return {
            "success": False, 
            "error": "Failed to parse nmap XML output.",
            "educational_note": "Nmap output parsing failed. This may indicate an nmap version compatibility issue."
        }
    except Exception as ex:
        return {
            "success": False, 
            "error": str(ex),
            "educational_note": "Unexpected error during port scan. Check target format and network connectivity."
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
