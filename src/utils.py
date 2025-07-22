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
    Validates an IP address and provides detailed error information.
    
    Args:
        ip_address: The string to validate as an IP address
        
    Returns:
        Tuple of (is_valid, error_message, suggestion)
    """
    if not ip_address or not isinstance(ip_address, str):
        return False, "IP address cannot be empty", "Please provide a valid IP address like 192.168.1.1 or 2001:db8::1"
    
    ip_address = ip_address.strip()
    
    if not ip_address:
        return False, "IP address cannot be empty", "Please provide a valid IP address like 192.168.1.1 or 2001:db8::1"
    
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
        
        # Additional validation for special cases
        if parsed_ip.is_loopback:
            return True, None, "Note: This is a loopback address (localhost)"
        elif parsed_ip.is_private:
            return True, None, "Note: This is a private network address"
        elif parsed_ip.is_multicast:
            return True, None, "Note: This is a multicast address"
        elif parsed_ip.is_reserved:
            return True, None, "Note: This is a reserved address"
        
        return True, None, None
        
    except ValueError as e:
        error_msg = str(e).lower()
        
        # Provide specific suggestions based on common errors
        if "does not appear to be an ipv4 or ipv6 address" in error_msg:
            # Check for common mistakes
            if '.' in ip_address and ip_address.count('.') == 3:
                parts = ip_address.split('.')
                invalid_parts = []
                for p in parts:
                    if not p.isdigit():
                        invalid_parts.append(f"'{p}' (not a number)")
                    elif int(p) > 255:
                        invalid_parts.append(f"'{p}' (must be 0-255)")
                if invalid_parts:
                    return False, f"Invalid IPv4 address: {', '.join(invalid_parts)}", "Each part must be a number between 0-255"
            elif ':' in ip_address:
                return False, "Invalid IPv6 address format", "IPv6 addresses use hexadecimal digits (0-9, a-f) separated by colons"
            else:
                return False, "Invalid IP address format", "Use IPv4 format (e.g., 192.168.1.1) or IPv6 format (e.g., 2001:db8::1)"
        
        return False, f"Invalid IP address: {str(e)}", "Please check the format and try again"

def validate_hostname(hostname: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a hostname and provides detailed error information and suggestions.
    
    Args:
        hostname: The string to validate as a hostname
        
    Returns:
        Tuple of (is_valid, error_message, suggestion)
    """
    if not hostname or not isinstance(hostname, str):
        return False, "Hostname cannot be empty", "Please provide a hostname like google.com or server.local"
    
    hostname = hostname.strip().lower()
    
    if not hostname:
        return False, "Hostname cannot be empty", "Please provide a hostname like google.com or server.local"
    
    # Check length constraints (RFC 1035)
    if len(hostname) > 253:
        return False, "Hostname too long (max 253 characters)", "Try using a shorter hostname"
    
    # Check for invalid characters
    if not re.match(r'^[a-z0-9.-]+$', hostname):
        invalid_chars = set(hostname) - set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        return False, f"Invalid characters in hostname: {', '.join(sorted(invalid_chars))}", "Hostnames can only contain letters, numbers, dots, and hyphens"
    
    # Check for consecutive dots or hyphens
    if '..' in hostname:
        return False, "Consecutive dots not allowed in hostname", "Remove extra dots (e.g., 'example..com' → 'example.com')"
    
    if '--' in hostname:
        return False, "Consecutive hyphens not allowed in hostname", "Remove extra hyphens"
    
    # Check if starts or ends with dot or hyphen
    if hostname.startswith('.') or hostname.endswith('.'):
        return False, "Hostname cannot start or end with a dot", "Remove leading/trailing dots"
    
    if hostname.startswith('-') or hostname.endswith('-'):
        return False, "Hostname cannot start or end with a hyphen", "Remove leading/trailing hyphens"
    
    # Split into labels and validate each
    labels = hostname.split('.')
    
    for label in labels:
        if not label:
            return False, "Empty label in hostname", "Check for consecutive dots"
        
        if len(label) > 63:
            return False, f"Label '{label}' too long (max 63 characters)", "Shorten individual parts of the hostname"
        
        if label.startswith('-') or label.endswith('-'):
            return False, f"Label '{label}' cannot start or end with hyphen", "Remove hyphens from start/end of hostname parts"
    
    # Check if it looks like a valid domain
    if len(labels) == 1:
        # Single label - might be a local hostname
        return True, None, "Note: This appears to be a local hostname (no domain)"
    
    # Check TLD (last label)
    tld = labels[-1]
    if tld.isdigit():
        return False, "Top-level domain cannot be all numbers", "Use a proper domain extension like .com, .org, .net"
    
    if len(tld) < 2:
        return False, "Top-level domain too short", "Use a proper domain extension like .com, .org, .net"
    
    # Common typo suggestions
    suggestions = []
    if hostname.endswith('.co'):
        suggestions.append("Did you mean .com?")
    elif hostname.endswith('.cm'):
        suggestions.append("Did you mean .com?")
    elif hostname.endswith('.og'):
        suggestions.append("Did you mean .org?")
    elif hostname.endswith('.nte'):
        suggestions.append("Did you mean .net?")
    
    suggestion = suggestions[0] if suggestions else None
    
    return True, None, suggestion

def validate_target(target: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a target (IP address or hostname) and provides detailed error information.
    
    Args:
        target: The target to validate (IP address or hostname)
        
    Returns:
        Tuple of (is_valid, error_message, suggestion)
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty", "Please provide an IP address or hostname"
    
    target = target.strip()
    
    if not target:
        return False, "Target cannot be empty", "Please provide an IP address or hostname"
    
    # First try IP validation
    is_valid_ip, ip_error, ip_suggestion = validate_ip_with_details(target)
    if is_valid_ip:
        return True, None, ip_suggestion
    
    # If not a valid IP, try hostname validation
    is_valid_hostname, hostname_error, hostname_suggestion = validate_hostname(target)
    if is_valid_hostname:
        return True, None, hostname_suggestion
    
    # Neither IP nor hostname is valid
    return False, f"Invalid target: {ip_error or hostname_error}", "Please provide a valid IP address (e.g., 192.168.1.1) or hostname (e.g., google.com)"

def validate_port(port: Union[str, int]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a port number and provides detailed error information.
    
    Args:
        port: The port number to validate (string or integer)
        
    Returns:
        Tuple of (is_valid, error_message, suggestion)
    """
    if port is None:
        return False, "Port cannot be empty", "Please provide a port number between 1 and 65535"
    
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port format: '{port}'", "Port must be a number between 1 and 65535"
    
    if port_num < 1:
        return False, f"Port number too low: {port_num}", "Port numbers must be between 1 and 65535"
    
    if port_num > 65535:
        return False, f"Port number too high: {port_num}", "Port numbers must be between 1 and 65535"
    
    # Provide context for common ports
    suggestions = []
    if port_num < 1024:
        suggestions.append("Note: This is a privileged port (requires root access)")
    
    common_ports = {
        22: "SSH (Secure Shell)",
        23: "Telnet (insecure - avoid)",
        25: "SMTP (email sending)",
        53: "DNS (domain name resolution)",
        80: "HTTP (web server)",
        443: "HTTPS (secure web server)",
        993: "IMAPS (secure email)",
        3389: "RDP (Windows remote desktop)"
    }
    
    if port_num in common_ports:
        suggestions.append(f"Common service: {common_ports[port_num]}")
    
    suggestion = "; ".join(suggestions) if suggestions else None
    
    return True, None, suggestion

def create_validation_error(field_name: str, value: str, error_msg: str, suggestion: str = None) -> dict:
    """
    Creates a standardized validation error response.
    
    Args:
        field_name: Name of the field that failed validation
        value: The invalid value
        error_msg: The error message
        suggestion: Optional suggestion for fixing the error
        
    Returns:
        Standardized error dictionary
    """
    error_response = {
        "success": False,
        "error": f"Invalid {field_name}: {error_msg}",
        "field": field_name,
        "invalid_value": value,
        "validation_details": {
            "message": error_msg,
            "suggestion": suggestion or f"Please provide a valid {field_name}",
            "examples": _get_validation_examples(field_name)
        }
    }
    
    return error_response

def _get_validation_examples(field_name: str) -> List[str]:
    """Get example values for different field types."""
    examples = {
        "IP address": ["192.168.1.1", "10.0.0.1", "2001:db8::1", "::1"],
        "hostname": ["google.com", "server.local", "example.org", "my-server.company.com"],
        "port": ["80", "443", "22", "8080"],
        "target": ["192.168.1.1", "google.com", "server.local"]
    }
    
    return examples.get(field_name, [])

def handle_network_timeout(operation: str, target: str, timeout_seconds: int = None) -> dict:
    """
    Creates a standardized network timeout error response with troubleshooting guidance.
    
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
        "error_type": "network_timeout",
        "troubleshooting": {
            "possible_causes": [
                "Target host is down or unreachable",
                "Network connectivity issues",
                "Firewall blocking the connection",
                "DNS resolution problems",
                "Network congestion or high latency"
            ],
            "suggested_actions": [
                f"Verify {target} is reachable with a basic ping test",
                "Check your network connection",
                "Try the operation again in a few moments",
                "Verify the target address is correct",
                "Check if a firewall is blocking the connection"
            ],
            "next_steps": [
                f"ping {target}",
                f"traceroute {target}",
                f"nslookup {target}"
            ]
        },
        "educational_note": f"{operation} timeouts often indicate network connectivity issues. The target may be down, unreachable, or protected by a firewall."
    }

def handle_dns_resolution_error(hostname: str, error_details: str = None) -> dict:
    """
    Creates a standardized DNS resolution error response with troubleshooting guidance.
    
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
        "details": error_details,
        "troubleshooting": {
            "possible_causes": [
                "Domain name does not exist",
                "DNS server is unreachable",
                "Temporary DNS server issues",
                "Network connectivity problems",
                "Incorrect domain name spelling"
            ],
            "suggested_actions": [
                "Check the spelling of the domain name",
                "Try using a different DNS server (8.8.8.8 or 1.1.1.1)",
                "Wait a few minutes and try again",
                "Check your internet connection",
                "Verify the domain exists by checking it in a web browser"
            ],
            "common_mistakes": [
                "Missing or incorrect top-level domain (.com, .org, .net)",
                "Typos in domain name",
                "Using internal hostnames without proper DNS setup"
            ]
        },
        "educational_note": "DNS (Domain Name System) translates human-readable domain names to IP addresses. Resolution failures usually indicate the domain doesn't exist or DNS servers are unreachable."
    }

def handle_connection_refused_error(target: str, port: int = None, service: str = None) -> dict:
    """
    Creates a standardized connection refused error response with troubleshooting guidance.
    
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
        "error_type": "connection_refused",
        "troubleshooting": {
            "possible_causes": [
                f"No service is running{port_info} on {target}",
                "Service is down or crashed",
                "Firewall is blocking the connection",
                "Service is configured to reject connections",
                "Wrong port number specified"
            ],
            "suggested_actions": [
                f"Verify the service is running on {target}",
                f"Check if the correct port number is being used",
                "Confirm the service accepts connections from your location",
                "Check firewall settings on both client and server",
                "Try connecting from the same network as the target"
            ],
            "diagnostic_commands": [
                f"nmap -p {port} {target}" if port else f"nmap {target}",
                f"telnet {target} {port}" if port else None,
                f"ping {target}"
            ]
        },
        "educational_note": "Connection refused means the target host is reachable but no service is listening on the specified port, or the service is actively rejecting connections."
    }

def handle_permission_denied_error(operation: str, additional_info: str = None) -> dict:
    """
    Creates a standardized permission denied error response with troubleshooting guidance.
    
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
        "additional_info": additional_info,
        "troubleshooting": {
            "possible_causes": [
                "Insufficient user privileges",
                "Operation requires administrator/root access",
                "Security policy blocking the operation",
                "File or resource permissions are restrictive"
            ],
            "suggested_actions": [
                "Try running with elevated privileges (sudo/administrator)",
                "Check if your user account has necessary permissions",
                "Contact system administrator if in corporate environment",
                "Verify the operation is allowed by security policies"
            ],
            "security_note": "Permission restrictions are often in place for security reasons"
        },
        "educational_note": f"Permission denied errors occur when the current user lacks sufficient privileges to perform {operation}."
    }

def handle_command_not_found_error(command: str, alternatives: List[str] = None) -> dict:
    """
    Creates a standardized command not found error response with alternatives.
    
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
        "troubleshooting": {
            "possible_causes": [
                f"'{command}' is not installed on this system",
                f"'{command}' is not in the system PATH",
                "Package containing the command is not installed",
                "Command name is misspelled"
            ],
            "suggested_actions": [
                f"Install the package containing '{command}'",
                f"Check if '{command}' is available in a different location",
                "Verify the command name spelling",
                "Update your system's package list"
            ],
            "alternatives": alternatives or [],
            "installation_hints": _get_installation_hints(command)
        },
        "educational_note": f"'{command}' is a network utility that may need to be installed separately on some systems."
    }

def _get_installation_hints(command: str) -> List[str]:
    """Get installation hints for common network commands."""
    installation_hints = {
        'ping': [
            "Usually pre-installed on most systems",
            "Part of iputils package on Linux",
            "Available by default on Windows and macOS"
        ],
        'traceroute': [
            "Install with: apt-get install traceroute (Ubuntu/Debian)",
            "Install with: yum install traceroute (CentOS/RHEL)",
            "Use 'tracert' on Windows instead"
        ],
        'nmap': [
            "Install with: apt-get install nmap (Ubuntu/Debian)",
            "Install with: yum install nmap (CentOS/RHEL)",
            "Download from: https://nmap.org/download.html"
        ],
        'netstat': [
            "Usually part of net-tools package",
            "Install with: apt-get install net-tools (Ubuntu/Debian)",
            "Consider using 'ss' as a modern alternative"
        ]
    }
    
    return installation_hints.get(command, [f"Search for '{command}' in your system's package manager"])

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
        is_valid, error_msg, suggestion = validate_target(kwargs['host'])
        if not is_valid:
            validation_errors.append(create_validation_error("target host", kwargs['host'], error_msg, suggestion))
    
    if 'target' in kwargs:
        is_valid, error_msg, suggestion = validate_target(kwargs['target'])
        if not is_valid:
            validation_errors.append(create_validation_error("target", kwargs['target'], error_msg, suggestion))
    
    if 'src_ip' in kwargs:
        is_valid, error_msg, suggestion = validate_ip_with_details(kwargs['src_ip'])
        if not is_valid:
            validation_errors.append(create_validation_error("source IP address", kwargs['src_ip'], error_msg, suggestion))
    
    if 'dst_ip' in kwargs:
        is_valid, error_msg, suggestion = validate_ip_with_details(kwargs['dst_ip'])
        if not is_valid:
            validation_errors.append(create_validation_error("destination IP address", kwargs['dst_ip'], error_msg, suggestion))
    
    if 'port' in kwargs:
        is_valid, error_msg, suggestion = validate_port(kwargs['port'])
        if not is_valid:
            validation_errors.append(create_validation_error("port", kwargs['port'], error_msg, suggestion))
    
    if 'top_ports' in kwargs:
        is_valid, error_msg, suggestion = validate_port(kwargs['top_ports'])
        if not is_valid:
            validation_errors.append(create_validation_error("port count", kwargs['top_ports'], error_msg, suggestion))
        elif int(kwargs['top_ports']) > 1000:
            validation_errors.append(create_validation_error("port count", kwargs['top_ports'], "Port count too high (max 1000)", "Use a smaller number to avoid excessive scan time"))
    
    # Operation-specific validations
    if operation == 'generate_acl':
        if 'action' in kwargs and kwargs['action'] not in ['permit', 'deny']:
            validation_errors.append(create_validation_error("action", kwargs['action'], "Action must be either 'permit' or 'deny'", "Use 'permit' to allow traffic or 'deny' to block traffic"))
    
    if operation == 'run_command':
        if 'cmd' in kwargs:
            cmd = kwargs['cmd']
            if not cmd or not isinstance(cmd, str) or not cmd.strip():
                validation_errors.append(create_validation_error("command", str(cmd), "Command cannot be empty", "Please provide a valid shell command"))
            else:
                # Basic command sanitization
                dangerous_patterns = [';', '&&', '||', '|', '>', '>>', '<', '`', '$()']
                if any(pattern in cmd for pattern in dangerous_patterns):
                    validation_errors.append({
                        "success": False,
                        "error": "Command contains potentially dangerous characters",
                        "field": "command",
                        "invalid_value": cmd,
                        "security_note": "For security reasons, commands with shell operators are not allowed",
                        "suggestion": "Use simple commands without pipes, redirects, or command chaining"
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
    Provides educational context and color-coded output for different network operations.
    
    Args:
        data: Dictionary containing operation results
        
    Returns:
        Formatted string with colors, explanations, and visual structure
    """
    if not isinstance(data, dict):
        return str(data)

    # Handle error cases with enhanced formatting
    if data.get("success") is False:
        error_message = data.get("error", "An unknown error occurred.")
        formatted_lines = []
        formatted_lines.append(f"{Colors.RED}{Colors.BOLD}❌ OPERATION FAILED{Colors.END}")
        formatted_lines.append(f"{Colors.RED}Error: {error_message}{Colors.END}")
        
        # Add validation details if available
        if "validation_details" in data:
            details = data["validation_details"]
            formatted_lines.append(f"\n{Colors.YELLOW}💡 {details['suggestion']}{Colors.END}")
            if details.get("examples"):
                formatted_lines.append(f"{Colors.CYAN}Examples: {', '.join(details['examples'])}{Colors.END}")
        
        # Add troubleshooting information if available
        if "troubleshooting" in data:
            troubleshooting = data["troubleshooting"]
            formatted_lines.append(f"\n{Colors.YELLOW}🔧 Troubleshooting:{Colors.END}")
            
            if "possible_causes" in troubleshooting:
                formatted_lines.append(f"{Colors.CYAN}Possible causes:{Colors.END}")
                for cause in troubleshooting["possible_causes"][:3]:  # Limit to 3 causes
                    formatted_lines.append(f"  • {cause}")
            
            if "suggested_actions" in troubleshooting:
                formatted_lines.append(f"{Colors.CYAN}Suggested actions:{Colors.END}")
                for action in troubleshooting["suggested_actions"][:3]:  # Limit to 3 actions
                    formatted_lines.append(f"  • {action}")
        
        # Add educational note if available
        if "educational_note" in data:
            formatted_lines.append(f"\n{Colors.MAGENTA}📚 {data['educational_note']}{Colors.END}")
        
        return '\n'.join(formatted_lines)

    # Handle successful outputs
    output = data.get("output")
    
    if output is None:
        # Handle cases where there's no specific 'output' key
        clean_data = {k: v for k, v in data.items() if k not in ["success", "educational_context"]}
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        
        if clean_data:
            formatted_lines.append(json.dumps(clean_data, indent=2))
        
        # Add educational context if available
        if "educational_context" in data:
            context = data["educational_context"]
            formatted_lines.append(f"\n{Colors.CYAN}📚 Educational Context:{Colors.END}")
            for key, value in context.items():
                if isinstance(value, str):
                    formatted_lines.append(f"{Colors.YELLOW}{key.replace('_', ' ').title()}:{Colors.END} {value}")
        
        return '\n'.join(formatted_lines)

    # Format based on output type
    if isinstance(output, str):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Output:{Colors.END}")
        formatted_lines.append(output)
        
        # Add educational context if available
        if "educational_context" in data:
            context = data["educational_context"]
            formatted_lines.append(f"\n{Colors.CYAN}📚 Educational Context:{Colors.END}")
            for key, value in context.items():
                if isinstance(value, str):
                    formatted_lines.append(f"{Colors.YELLOW}{key.replace('_', ' ').title()}:{Colors.END} {value}")
        
        return '\n'.join(formatted_lines)
    
    # Handle other structured data
    elif isinstance(output, (dict, list)):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Results:{Colors.END}")
        formatted_lines.append(json.dumps(output, indent=2))
        return '\n'.join(formatted_lines)
        
    return str(output)