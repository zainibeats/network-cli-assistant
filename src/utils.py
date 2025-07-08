# src/utils.py

"""
Utility functions and helper classes.

This module can be used for common tasks like:
- Data validation
- Text formatting
- Reading configuration files
"""

import ipaddress
import inspect
from src import core_functions

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
    Formats a dictionary for clean printing to the console.
    """
    # Hint: The 'json' or 'pprint' modules can be useful for pretty-printing.
    # You could also add colors using a library like 'rich' or 'colorama'
    # to make the output more readable (e.g., green for success, red for errors).
    import json
    return json.dumps(data, indent=2)
