# src/utils.py

"""
Utility functions and helper classes.

This module can be used for common tasks like:
- Data validation
- Text formatting
- Reading configuration files
"""

import ipaddress
import json
import re
import socket
import subprocess
import time
from typing import Dict, List, Any, Union, Tuple, Optional

# Color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def validate_ip(ip_address: str) -> bool:
    """
    Checks if a given string is a valid IPv4 or IPv6 address.

    Args:
        ip_address: The string to validate.

    Returns:
        True if the string is a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def validate_ip_with_details(ip_address: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates an IP address and provides error information.
    
    Args:
        ip_address: The string to validate as an IP address
        
    Returns:
        Tuple of (is_valid, error_message, None)
    """
    if not ip_address or not isinstance(ip_address, str):
        return False, "IP address cannot be empty", None
    
    ip_address = ip_address.strip()
    
    if not ip_address:
        return False, "IP address cannot be empty", None
    
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
        return True, None, None
        
    except ValueError as e:
        return False, f"Invalid IP address: {str(e)}", None

def validate_hostname(hostname: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a hostname and provides error information.
    
    Args:
        hostname: The string to validate as a hostname
        
    Returns:
        Tuple of (is_valid, error_message, None)
    """
    if not hostname or not isinstance(hostname, str):
        return False, "Hostname cannot be empty", None
    
    hostname = hostname.strip().lower()
    
    if not hostname:
        return False, "Hostname cannot be empty", None
    
    # Check length constraints (RFC 1035)
    if len(hostname) > 253:
        return False, "Hostname too long (max 253 characters)", None
    
    # Check for invalid characters
    if not re.match(r'^[a-z0-9.-]+$', hostname):
        invalid_chars = set(hostname) - set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        return False, f"Invalid characters in hostname: {', '.join(sorted(invalid_chars))}", None
    
    # Check for consecutive dots or hyphens
    if '..' in hostname:
        return False, "Consecutive dots not allowed in hostname", None
    
    if '--' in hostname:
        return False, "Consecutive hyphens not allowed in hostname", None
    
    # Check if starts or ends with dot or hyphen
    if hostname.startswith('.') or hostname.endswith('.'):
        return False, "Hostname cannot start or end with a dot", None
    
    if hostname.startswith('-') or hostname.endswith('-'):
        return False, "Hostname cannot start or end with a hyphen", None
    
    # Split into labels and validate each
    labels = hostname.split('.')
    
    for label in labels:
        if not label:
            return False, "Empty label in hostname", None
        
        if len(label) > 63:
            return False, f"Label '{label}' too long (max 63 characters)", None
        
        if label.startswith('-') or label.endswith('-'):
            return False, f"Label '{label}' cannot start or end with hyphen", None
    
    # Check TLD (last label)
    if len(labels) > 1:
        tld = labels[-1]
        if tld.isdigit():
            return False, "Top-level domain cannot be all numbers", None
        
        if len(tld) < 2:
            return False, "Top-level domain too short", None
    
    return True, None, None

def validate_target(target: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a target (IP address or hostname).
    
    Args:
        target: The target to validate (IP address or hostname)
        
    Returns:
        Tuple of (is_valid, error_message, None)
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty", None
    
    target = target.strip()
    
    if not target:
        return False, "Target cannot be empty", None
    
    # First try IP validation
    is_valid_ip, ip_error, _ = validate_ip_with_details(target)
    if is_valid_ip:
        return True, None, None
    
    # If not a valid IP, try hostname validation
    is_valid_hostname, hostname_error, _ = validate_hostname(target)
    if is_valid_hostname:
        return True, None, None
    
    # Neither IP nor hostname is valid
    return False, f"Invalid target: {ip_error or hostname_error}", None

def validate_network_target(target: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a network target (IP address, hostname, or CIDR notation).
    
    Args:
        target: The target to validate (IP address, hostname, or CIDR like 192.168.1.0/24)
        
    Returns:
        Tuple of (is_valid, error_message, target_type)
        target_type can be: 'ip', 'hostname', 'cidr', or None
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty", None
    
    target = target.strip()
    
    if not target:
        return False, "Target cannot be empty", None
    
    # Check if it's CIDR notation
    if '/' in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            return True, None, 'cidr'
        except ValueError as e:
            return False, f"Invalid CIDR notation: {str(e)}", None
    
    # First try IP validation
    is_valid_ip, ip_error, _ = validate_ip_with_details(target)
    if is_valid_ip:
        return True, None, 'ip'
    
    # If not a valid IP, try hostname validation
    is_valid_hostname, hostname_error, _ = validate_hostname(target)
    if is_valid_hostname:
        return True, None, 'hostname'
    
    # Neither IP, hostname, nor CIDR is valid
    return False, f"Invalid target: {ip_error or hostname_error}", None

def validate_port(port: Union[str, int]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a port number.
    
    Args:
        port: The port number to validate (string or integer)
        
    Returns:
        Tuple of (is_valid, error_message, None)
    """
    if port is None:
        return False, "Port cannot be empty", None
    
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port format: '{port}'", None
    
    if port_num < 1:
        return False, f"Port number too low: {port_num}", None
    
    if port_num > 65535:
        return False, f"Port number too high: {port_num}", None
    
    return True, None, None

def create_validation_error(field_name: str, value: str, error_msg: str, suggestion: str = None) -> dict:
    """
    Creates a standardized validation error response.
    
    Args:
        field_name: Name of the field that failed validation
        value: The invalid value
        error_msg: The error message
        suggestion: Unused parameter (kept for compatibility)
        
    Returns:
        Standardized error dictionary
    """
    return {
        "success": False,
        "error": f"Invalid {field_name}: {error_msg}",
        "field": field_name,
        "invalid_value": value,
        "error_type": "validation_error"
    }

def handle_network_timeout(operation: str, target: str, timeout_seconds: int = None) -> dict:
    """
    Creates a standardized network timeout error response.
    
    Args:
        operation: The network operation that timed out
        target: The target host/IP that was unreachable
        timeout_seconds: The timeout duration if known
        
    Returns:
        Standardized timeout error dictionary
    """
    timeout_msg = f" after {timeout_seconds} seconds" if timeout_seconds else ""
    
    return {
        "success": False,
        "error": f"{operation} operation timed out{timeout_msg}",
        "target": target,
        "error_type": "network_timeout"
    }

def handle_dns_resolution_error(hostname: str, error_details: str = None) -> dict:
    """
    Creates a standardized DNS resolution error response.
    
    Args:
        hostname: The hostname that failed to resolve
        error_details: Additional error details if available
        
    Returns:
        Standardized DNS error dictionary
    """
    return {
        "success": False,
        "error": f"DNS resolution failed for '{hostname}'",
        "hostname": hostname,
        "error_type": "dns_resolution",
        "details": error_details
    }

def handle_connection_refused_error(target: str, port: int = None, service: str = None) -> dict:
    """
    Creates a standardized connection refused error response.
    
    Args:
        target: The target host that refused the connection
        port: The port number if applicable
        service: The service name if known
        
    Returns:
        Standardized connection refused error dictionary
    """
    port_info = f" on port {port}" if port else ""
    service_info = f" ({service})" if service else ""
    
    return {
        "success": False,
        "error": f"Connection refused by {target}{port_info}{service_info}",
        "target": target,
        "port": port,
        "service": service,
        "error_type": "connection_refused"
    }

def handle_permission_denied_error(operation: str, additional_info: str = None) -> dict:
    """
    Creates a standardized permission denied error response.
    
    Args:
        operation: The operation that was denied
        additional_info: Additional context about the permission issue
        
    Returns:
        Standardized permission denied error dictionary
    """
    return {
        "success": False,
        "error": f"Permission denied for {operation}",
        "error_type": "permission_denied",
        "additional_info": additional_info
    }

def handle_command_not_found_error(command: str, alternatives: List[str] = None) -> dict:
    """
    Creates a standardized command not found error response.
    
    Args:
        command: The command that was not found
        alternatives: List of alternative commands to suggest
        
    Returns:
        Standardized command not found error dictionary
    """
    return {
        "success": False,
        "error": f"Command '{command}' not found",
        "error_type": "command_not_found",
        "missing_command": command,
        "alternatives": alternatives or []
    }



def validate_network_operation_input(operation: str, **kwargs) -> Tuple[bool, Optional[dict]]:
    """
    Comprehensive validation for network operations with detailed error reporting.
    
    Args:
        operation: The network operation being performed
        **kwargs: Operation-specific parameters to validate
        
    Returns:
        Tuple of (is_valid, error_response_dict_if_invalid)
    """
    validation_errors = []
    
    # Common parameter validations
    if 'host' in kwargs:
        is_valid, error_msg, _ = validate_target(kwargs['host'])
        if not is_valid:
            validation_errors.append(create_validation_error("target host", kwargs['host'], error_msg))
    
    if 'target' in kwargs:
        # For nmap operations, use network target validation that supports CIDR
        if operation == 'run_nmap_scan':
            is_valid, error_msg, _ = validate_network_target(kwargs['target'])
        else:
            is_valid, error_msg, _ = validate_target(kwargs['target'])
        if not is_valid:
            validation_errors.append(create_validation_error("target", kwargs['target'], error_msg))
    
    if 'network' in kwargs:
        # For host discovery operations, use network target validation that supports CIDR
        if operation == 'discover_hosts':
            is_valid, error_msg, _ = validate_network_target(kwargs['network'])
            if not is_valid:
                validation_errors.append(create_validation_error("network", kwargs['network'], error_msg))
    
    if 'src_ip' in kwargs:
        is_valid, error_msg, _ = validate_ip_with_details(kwargs['src_ip'])
        if not is_valid:
            validation_errors.append(create_validation_error("source IP address", kwargs['src_ip'], error_msg))
    
    if 'dst_ip' in kwargs:
        is_valid, error_msg, _ = validate_ip_with_details(kwargs['dst_ip'])
        if not is_valid:
            validation_errors.append(create_validation_error("destination IP address", kwargs['dst_ip'], error_msg))
    
    if 'port' in kwargs:
        is_valid, error_msg, _ = validate_port(kwargs['port'])
        if not is_valid:
            validation_errors.append(create_validation_error("port", kwargs['port'], error_msg))
    
    if 'top_ports' in kwargs:
        is_valid, error_msg, _ = validate_port(kwargs['top_ports'])
        if not is_valid:
            validation_errors.append(create_validation_error("port count", kwargs['top_ports'], error_msg))
        elif int(kwargs['top_ports']) > 1000:
            validation_errors.append(create_validation_error("port count", kwargs['top_ports'], "Port count too high (max 1000)"))
    
    # Operation-specific validations
    if operation == 'generate_acl':
        if 'action' in kwargs and kwargs['action'] not in ['permit', 'deny']:
            validation_errors.append(create_validation_error("action", kwargs['action'], "Action must be either 'permit' or 'deny'"))
    
    if operation == 'run_command':
        if 'cmd' in kwargs:
            cmd = kwargs['cmd']
            if not cmd or not isinstance(cmd, str) or not cmd.strip():
                validation_errors.append(create_validation_error("command", str(cmd), "Command cannot be empty"))
            else:
                # Basic command sanitization
                dangerous_patterns = [';', '&&', '||', '|', '>', '>>', '<', '`', '$()']
                if any(pattern in cmd for pattern in dangerous_patterns):
                    validation_errors.append({
                        "success": False,
                        "error": "Command contains potentially dangerous characters",
                        "field": "command",
                        "invalid_value": cmd,
                        "security_note": "For security reasons, commands with shell operators are not allowed"
                    })
    
    if validation_errors:
        # Return the first validation error (they're all structured the same way)
        return False, validation_errors[0]
    
    return True, None

def retry_network_operation(operation_func, max_retries: int = 3, delay_seconds: float = 1.0, backoff_multiplier: float = 2.0):
    """
    Decorator to add retry logic to network operations with exponential backoff.
    
    Args:
        operation_func: The network operation function to retry
        max_retries: Maximum number of retry attempts
        delay_seconds: Initial delay between retries
        backoff_multiplier: Multiplier for exponential backoff
        
    Returns:
        Wrapped function with retry logic
    """
    def wrapper(*args, **kwargs):
        last_exception = None
        current_delay = delay_seconds
        
        for attempt in range(max_retries + 1):  # +1 for initial attempt
            try:
                result = operation_func(*args, **kwargs)
                
                # If the operation returned a success=False dict, don't retry certain error types
                if isinstance(result, dict) and not result.get("success", True):
                    error_type = result.get("error_type", "")
                    # Don't retry validation errors or permission errors
                    if error_type in ["validation_error", "permission_denied", "command_not_found"]:
                        return result
                    
                    # For network errors, continue with retry logic
                    if attempt < max_retries:
                        time.sleep(current_delay)
                        current_delay *= backoff_multiplier
                        continue
                
                return result
                
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    time.sleep(current_delay)
                    current_delay *= backoff_multiplier
                else:
                    # Final attempt failed, return error
                    return {
                        "success": False,
                        "error": f"Operation failed after {max_retries + 1} attempts: {str(e)}",
                        "error_type": "retry_exhausted",
                        "attempts_made": max_retries + 1,
                        "last_error": str(last_exception) if last_exception else str(e)
                    }
        
        # This shouldn't be reached, but just in case
        return {
            "success": False,
            "error": "Unexpected error in retry logic",
            "error_type": "retry_logic_error"
        }
    
    return wrapper

def format_output(data: dict) -> str:
    """
    Formats a dictionary for clean, human-readable printing to the console.
    
    Args:
        data: Dictionary containing operation results
        
    Returns:
        Formatted string with colors and basic structure
    """
    if not isinstance(data, dict):
        return str(data)

    # Handle error cases with basic formatting
    if data.get("success") is False:
        error_message = data.get("error", "An unknown error occurred.")
        formatted_lines = []
        formatted_lines.append(f"{Colors.RED}{Colors.BOLD}❌ OPERATION FAILED{Colors.END}")
        formatted_lines.append(f"{Colors.RED}Error: {error_message}{Colors.END}")
        
        # Add error type if available
        if "error_type" in data:
            formatted_lines.append(f"{Colors.YELLOW}Type: {data['error_type']}{Colors.END}")
        
        return '\n'.join(formatted_lines)

    # Special handling for nmap results with interpretation
    if "interpretation" in data and "ports_found" in data:
        return _format_nmap_output(data)

    # Handle successful outputs
    output = data.get("output")
    
    if output is None:
        # Handle cases where there's no specific 'output' key
        clean_data = {k: v for k, v in data.items() if k not in ["success"]}
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        
        if clean_data:
            formatted_lines.append(json.dumps(clean_data, indent=2))
        
        return '\n'.join(formatted_lines)

    # Format based on output type
    if isinstance(output, str):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Output:{Colors.END}")
        formatted_lines.append(output)
        
        return '\n'.join(formatted_lines)
    
    # Handle other structured data
    elif isinstance(output, (dict, list)):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Results:{Colors.END}")
        formatted_lines.append(json.dumps(output, indent=2))
        return '\n'.join(formatted_lines)
        
    return str(output)

def _format_nmap_output(data: dict) -> str:
    """
    Formats nmap scan results with interpretation and security analysis.
    
    Args:
        data: Dictionary containing nmap scan results with interpretation
        
    Returns:
        Formatted string with security analysis and recommendations
    """
    formatted_lines = []
    interpretation = data.get("interpretation", {})
    ports_found = data.get("ports_found", [])
    host_info = data.get("host_info", {})
    
    # Check if this is a network scan with multiple hosts
    network_summary = data.get("network_summary")
    hosts_with_ports = data.get("hosts_with_ports", [])
    
    # Header with overall risk assessment
    overall_risk = interpretation.get("overall_risk", "unknown")
    risk_colors = {
        "critical": Colors.RED + Colors.BOLD,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.GREEN,
        "minimal": Colors.GREEN,
        "unknown": Colors.WHITE
    }
    
    risk_color = risk_colors.get(overall_risk, Colors.WHITE)
    formatted_lines.append(f"{Colors.GREEN}✅ Nmap scan completed{Colors.END}")
    formatted_lines.append(f"{Colors.BOLD}Security Risk Level: {risk_color}{overall_risk.upper()}{Colors.END}")
    
    # For network scans, show the network summary first
    if network_summary and len(hosts_with_ports) > 1:
        formatted_lines.append(f"\n{Colors.BOLD}Network Scan Results:{Colors.END}")
        formatted_lines.append(network_summary)
    
    # Summary
    summary = interpretation.get("summary", "Scan completed")
    formatted_lines.append(f"\n{Colors.BOLD}Summary:{Colors.END}")
    formatted_lines.append(f"{summary}")
    
    # Target information
    if host_info:
        formatted_lines.append(f"\n{Colors.BOLD}Target Information:{Colors.END}")
        if "ip" in host_info:
            formatted_lines.append(f"  IP Address: {host_info['ip']}")
        if "hostname" in host_info:
            formatted_lines.append(f"  Hostname: {host_info['hostname']}")
        if "status" in host_info:
            formatted_lines.append(f"  Status: {host_info['status']}")
    
    # Port details with security assessment
    if ports_found:
        formatted_lines.append(f"\n{Colors.BOLD}Open Ports and Security Assessment:{Colors.END}")
        
        for port_info in ports_found:
            if port_info["state"] == "open":
                port = port_info["port"]
                service = port_info["service"]
                risk = port_info["security_risk"]
                
                # Color code by risk level
                port_color = risk_colors.get(risk, Colors.WHITE)
                formatted_lines.append(f"  {port_color}Port {port} ({service}) - {risk.upper()} RISK{Colors.END}")
                
                # Add specific recommendations for this port
                recommendations = port_info.get("recommendations", [])
                if recommendations:
                    for rec in recommendations[:2]:  # Show first 2 recommendations
                        formatted_lines.append(f"    • {rec}")
                    if len(recommendations) > 2:
                        formatted_lines.append(f"    • ... and {len(recommendations) - 2} more recommendations")
    
    # Overall recommendations
    recommendations = interpretation.get("recommendations", [])
    if recommendations:
        formatted_lines.append(f"\n{Colors.BOLD}Security Recommendations:{Colors.END}")
        
        current_section = None
        for rec in recommendations:
            if rec.endswith(":"):
                # This is a section header
                current_section = rec
                if "IMMEDIATE" in rec or "CRITICAL" in rec:
                    formatted_lines.append(f"{Colors.RED}{Colors.BOLD}{rec}{Colors.END}")
                elif "HIGH PRIORITY" in rec:
                    formatted_lines.append(f"{Colors.YELLOW}{Colors.BOLD}{rec}{Colors.END}")
                else:
                    formatted_lines.append(f"{Colors.CYAN}{Colors.BOLD}{rec}{Colors.END}")
            else:
                # This is a recommendation item
                if rec.startswith("  •"):
                    # Indented item
                    if current_section and ("IMMEDIATE" in current_section or "CRITICAL" in current_section):
                        formatted_lines.append(f"{Colors.RED}{rec}{Colors.END}")
                    elif current_section and "HIGH PRIORITY" in current_section:
                        formatted_lines.append(f"{Colors.YELLOW}{rec}{Colors.END}")
                    else:
                        formatted_lines.append(f"{rec}")
                else:
                    formatted_lines.append(f"{rec}")
    
    # Risk breakdown summary
    risk_breakdown = interpretation.get("risk_breakdown", {})
    if any(count > 0 for count in risk_breakdown.values()):
        formatted_lines.append(f"\n{Colors.BOLD}Risk Breakdown:{Colors.END}")
        for risk_level, count in risk_breakdown.items():
            if count > 0:
                color = risk_colors.get(risk_level, Colors.WHITE)
                formatted_lines.append(f"  {color}{risk_level.capitalize()}: {count} service{'s' if count != 1 else ''}{Colors.END}")
    
    return '\n'.join(formatted_lines)