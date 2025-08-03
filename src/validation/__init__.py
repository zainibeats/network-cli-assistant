"""
Validation module.

This module provides validation functions for network inputs and general input validation.
"""

# Import all validation functions to maintain backward compatibility
from .network import (
    validate_ip,
    validate_ip_with_details,
    validate_hostname,
    validate_target,
    validate_network_target,
    validate_port
)
from .input import (
    create_validation_error,
    validate_network_operation_input,
    retry_network_operation
)

# Export all functions for easy importing
__all__ = [
    'validate_ip',
    'validate_ip_with_details',
    'validate_hostname', 
    'validate_target',
    'validate_network_target',
    'validate_port',
    'create_validation_error',
    'validate_network_operation_input',
    'retry_network_operation'
]