"""
Common error handling utilities.

This module provides general-purpose error handling functions and utilities.
"""

from typing import Any, Dict, Optional


def create_generic_error(error_message: str, error_type: str = "generic_error", **additional_fields) -> dict:
    """
    Creates a standardized generic error response.
    
    Args:
        error_message: The error message to display
        error_type: The type/category of error
        **additional_fields: Additional fields to include in the error response
        
    Returns:
        Standardized error dictionary
    """
    error_response = {
        "success": False,
        "error": error_message,
        "error_type": error_type
    }
    
    # Add any additional fields provided
    error_response.update(additional_fields)
    
    return error_response


def handle_unexpected_error(operation: str, exception: Exception, context: Dict[str, Any] = None) -> dict:
    """
    Creates a standardized unexpected error response.
    
    Args:
        operation: The operation that failed
        exception: The exception that was caught
        context: Additional context information about the error
        
    Returns:
        Standardized unexpected error dictionary
    """
    error_response = {
        "success": False,
        "error": f"Unexpected error during {operation}: {str(exception)}",
        "error_type": "unexpected_error",
        "operation": operation,
        "exception_type": type(exception).__name__
    }
    
    if context:
        error_response["context"] = context
    
    return error_response


def is_recoverable_error(error_dict: dict) -> bool:
    """
    Determines if an error is recoverable and should be retried.
    
    Args:
        error_dict: The error dictionary to check
        
    Returns:
        True if the error is recoverable, False otherwise
    """
    if not isinstance(error_dict, dict) or error_dict.get("success", True):
        return False
    
    # Non-recoverable error types
    non_recoverable_types = {
        "validation_error",
        "permission_denied", 
        "command_not_found",
        "security_violation",
        "parse_error"
    }
    
    error_type = error_dict.get("error_type", "")
    return error_type not in non_recoverable_types


def format_error_for_logging(error_dict: dict) -> str:
    """
    Formats an error dictionary for logging purposes.
    
    Args:
        error_dict: The error dictionary to format
        
    Returns:
        Formatted error string suitable for logging
    """
    if not isinstance(error_dict, dict):
        return str(error_dict)
    
    error_msg = error_dict.get("error", "Unknown error")
    error_type = error_dict.get("error_type", "unknown")
    
    log_parts = [f"[{error_type.upper()}] {error_msg}"]
    
    # Add additional context if available
    if "operation" in error_dict:
        log_parts.append(f"Operation: {error_dict['operation']}")
    
    if "target" in error_dict:
        log_parts.append(f"Target: {error_dict['target']}")
    
    if "context" in error_dict:
        log_parts.append(f"Context: {error_dict['context']}")
    
    return " | ".join(log_parts)