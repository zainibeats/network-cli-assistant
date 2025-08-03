"""
Error handling module.

This module provides standardized error handling functions for network and common errors.
"""

# Import all error handling functions
from .network import (
    handle_network_timeout,
    handle_dns_resolution_error,
    handle_connection_refused_error,
    handle_permission_denied_error,
    handle_command_not_found_error
)
from .common import (
    create_generic_error,
    handle_unexpected_error,
    is_recoverable_error,
    format_error_for_logging
)

# Export all functions for easy importing
__all__ = [
    'handle_network_timeout',
    'handle_dns_resolution_error',
    'handle_connection_refused_error',
    'handle_permission_denied_error',
    'handle_command_not_found_error',
    'create_generic_error',
    'handle_unexpected_error',
    'is_recoverable_error',
    'format_error_for_logging'
]