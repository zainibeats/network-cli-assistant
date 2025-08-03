"""
Port scanning functions for network security assessment.

This module provides functionality for port scanning using nmap and netstat.
"""

import subprocess
import logging
import time
import xml.etree.ElementTree as ET
from ..validation.network import validate_network_target, validate_port
from ..logging_config import log_operation, get_logger


@log_operation("nmap_scan")
def run_nmap_scan(target: str, top_ports: int = 10, port_range: str = None, specific_ports: str = None, timeout: int = 300) -> dict:
    """
    Performs a network port scan using Nmap to discover open services with enhanced configuration options.
    
    Args:
        target (str): The IP address, hostname, or subnet to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        top_ports (int): Number of most common ports to scan (default: 10, max: 65535)
        port_range (str): Port range to scan (e.g., "1-1000", "80-443", "1-65535")
        specific_ports (str): Comma-separated list of specific ports (e.g., "22,80,443,8080")
        timeout (int): Timeout in seconds for the scan operation (default: 300, max: 3600)

    Returns:
        dict: Contains scan results with progress information
    """
    # Validate target parameter (supports CIDR notation)
    is_valid_target, error_msg, target_type = validate_network_target(target)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    # Validate timeout parameter
    if not isinstance(timeout, int) or timeout < 10 or timeout > 3600:
        return {"success": False, "error": "Timeout must be between 10 and 3600 seconds"}
    
    # Validate port scanning options - only one should be specified
    port_options_count = sum(1 for x in [top_ports != 10, port_range is not None, specific_ports is not None] if x)
    if port_options_count > 1:
        return {"success": False, "error": "Only one port scanning option can be specified: top_ports, port_range, or specific_ports"}
    
    # Validate specific port options
    if specific_ports is not None:
        # Validate specific ports format
        try:
            ports = [int(p.strip()) for p in specific_ports.split(',')]
            if not all(1 <= p <= 65535 for p in ports):
                return {"success": False, "error": "All ports must be between 1 and 65535"}
            if len(ports) > 1000:
                return {"success": False, "error": "Too many specific ports (max 1000)"}
        except ValueError:
            return {"success": False, "error": "Invalid specific ports format. Use comma-separated numbers (e.g., '22,80,443')"}
    
    if port_range is not None:
        # Validate port range format
        try:
            if '-' not in port_range:
                return {"success": False, "error": "Port range must be in format 'start-end' (e.g., '1-1000')"}
            start_port, end_port = map(int, port_range.split('-', 1))
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                return {"success": False, "error": "Port range must be between 1 and 65535"}
            if start_port > end_port:
                return {"success": False, "error": "Start port must be less than or equal to end port"}
            port_count = end_port - start_port + 1
            if port_count > 10000:
                return {"success": False, "error": "Port range too large (max 10000 ports)"}
        except ValueError:
            return {"success": False, "error": "Invalid port range format. Use 'start-end' (e.g., '1-1000')"}
    
    if top_ports != 10:
        # Validate top_ports parameter
        is_valid_port, port_error, _ = validate_port(top_ports)
        if not is_valid_port:
            return {"success": False, "error": port_error}
        
        # Additional validation for port count range
        if top_ports > 65535:
            return {"success": False, "error": "Port count too high (max 65535)"}
    
    logger = logging.getLogger("network_cli.nmap")
    
    # Determine scan type and build command
    scan_description = ""
    cmd = ["nmap", "-T4"]  # Base command with timing template
    
    if specific_ports is not None:
        cmd.extend(["-p", specific_ports])
        scan_description = f"specific ports ({specific_ports})"
        estimated_time = len(specific_ports.split(',')) * 2  # Rough estimate
    elif port_range is not None:
        cmd.extend(["-p", port_range])
        scan_description = f"port range {port_range}"
        start_port, end_port = map(int, port_range.split('-'))
        port_count = end_port - start_port + 1
        estimated_time = min(port_count * 0.1, 60)  # Rough estimate, capped at 60s
    else:
        cmd.extend(["--top-ports", str(top_ports)])
        scan_description = f"top {top_ports} most common ports"
        estimated_time = top_ports * 0.5  # Rough estimate
    
    # Add progress and timeout options
    cmd.extend([
        "-oX", "-",  # Output as XML to stdout for easier parsing
        "--host-timeout", f"{timeout}s",  # Per-host timeout
        "--max-rtt-timeout", "2s",  # Maximum round-trip time
        "--initial-rtt-timeout", "500ms",  # Initial RTT timeout
    ])
    
    # Add target
    cmd.append(target)
    
    logger.info(f"Starting nmap scan of {target}", extra={
        "target": target,
        "scan_type": scan_description,
        "timeout": timeout,
        "estimated_time": estimated_time
    })
    
    print(f"Scanning {target} for open ports ({scan_description})...")
    if estimated_time > 30:
        print(f"This scan may take up to {int(estimated_time)} seconds. Please wait...")
    
    try:
        # Start the scan with progress tracking
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout + 30)
        
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

        # Calculate scan time and prepare results
        elapsed_time = time.time() - start_time
        
        # Determine actual ports scanned count
        if specific_ports is not None:
            ports_scanned_count = len(specific_ports.split(','))
        elif port_range is not None:
            start_port, end_port = map(int, port_range.split('-'))
            ports_scanned_count = end_port - start_port + 1
        else:
            ports_scanned_count = top_ports
        
        results = {
            "success": True,
            "target": target,
            "ports_scanned": ports_scanned_count,
            "scan_description": scan_description,
            "scan_time": round(elapsed_time, 2),
            "ports_found": parsed_output,
            "hosts_scanned": len(all_hosts),
            "hosts_with_ports": hosts_with_ports,
            # Keep host_info for backward compatibility (use first host if available)
            "host_info": all_hosts[0] if all_hosts else {}
        }

        if not parsed_output:
            logger.info(f"No open ports found on {target}")
            if len(all_hosts) > 1:
                results["output"] = f"Scanned {len(all_hosts)} hosts on {target} ({scan_description}) in {elapsed_time:.1f}s. No open ports found."
            else:
                results["output"] = f"No open or filtered ports found on {target} ({scan_description}) in {elapsed_time:.1f}s."
            results["interpretation"] = {
                "overall_risk": "minimal",
                "summary": f"No open ports detected on {target} - systems appear well secured or may be down",
                "recommendations": ["Verify targets are reachable", "Systems may have strong firewall protection"]
            }
        else:
            open_ports = [p for p in parsed_output if p.get("state") == "open"]
            logger.info(f"Nmap scan completed: found {len(open_ports)} open ports on {len(hosts_with_ports)} hosts", extra={
                "open_ports": [f"{p.get('host_ip')}:{p.get('port')}" for p in open_ports],
                "total_ports_scanned": ports_scanned_count,
                "hosts_with_ports": len(hosts_with_ports),
                "scan_time": elapsed_time,
                "scan_description": scan_description
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
            from ..network.analysis import interpret_nmap_results
            results["interpretation"] = interpret_nmap_results(results)

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