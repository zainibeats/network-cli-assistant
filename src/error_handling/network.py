"""
Network error handling functions.

This module provides standardized error handling functions for network-specific errors.
"""

from typing import List, Optional


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