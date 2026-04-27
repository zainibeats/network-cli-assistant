"""
Utility functions and helper classes.

This module now serves as a compatibility layer, importing all functions
from the new modular structure to maintain backward compatibility.
"""

# Import all functions from the new modular structure
from .error_handling import (
    handle_command_not_found_error,
    handle_connection_refused_error,
    handle_dns_resolution_error,
    handle_network_timeout,
    handle_permission_denied_error,
)
from .formatting import Colors, format_output
from .validation import (
    create_validation_error,
    retry_network_operation,
    validate_hostname,
    validate_ip,
    validate_ip_with_details,
    validate_network_operation_input,
    validate_network_target,
    validate_port,
    validate_target,
)

# Export all functions to maintain backward compatibility
__all__ = [
    "validate_ip",
    "validate_ip_with_details",
    "validate_hostname",
    "validate_target",
    "validate_network_target",
    "validate_port",
    "create_validation_error",
    "validate_network_operation_input",
    "retry_network_operation",
    "format_output",
    "Colors",
    "handle_network_timeout",
    "handle_dns_resolution_error",
    "handle_connection_refused_error",
    "handle_permission_denied_error",
    "handle_command_not_found_error",
]
