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

def validate_ip(ip_address: str) -> bool:
    """
    Checks if a given string is a valid IPv4 or IPv6 address.

    Args:
        ip_address: The string to validate.

    Returns:
        True if the string is a valid IP address, False otherwise.
    """
    # Hint: The 'ipaddress' module in the standard library is your friend here.
    # It can parse both IPv4 and IPv6 addresses with a single function call.
    # Remember to wrap it in a try...except block to handle invalid input gracefully.
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def format_output(data: dict) -> str:
    """
    Formats a dictionary for clean, human-readable printing to the console.
    """
    if not isinstance(data, dict):
        return str(data)

    if data.get("success") is False:
        error_message = data.get("error", "An unknown error occurred.")
        return f"❌ Error: {error_message}"

    output = data.get("output")
    if output is None:
        # Handle cases where there's no specific 'output' key but success is true
        # This could be for functions that return structured data directly
        # We can pretty-print the whole dictionary, excluding the 'success' flag
        data.pop("success", None)
        return json.dumps(data, indent=2)

    if isinstance(output, str):
        return f"✅ Success:\n---\n{output.strip()}\n---"
    
    # If output is a list or dict, pretty-print it
    if isinstance(output, (dict, list)):
        return f"✅ Success:\n---\n{json.dumps(output, indent=2)}\n---"
        
    return str(output)
