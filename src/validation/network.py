"""
Network-specific validation functions.

This module provides validation functions for network-related inputs like IP addresses,
hostnames, ports, and network targets.
"""

import ipaddress
import re
from typing import Tuple, Optional, Union


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