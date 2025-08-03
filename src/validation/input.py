"""
General input validation functions.

This module provides general-purpose validation functions for user inputs
and network operation parameters.
"""

import time
from typing import Dict, List, Any, Union, Tuple, Optional
from .network import validate_target, validate_network_target, validate_ip_with_details, validate_port


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