# src/utils.py

"""
Utility functions for the Network CLI Assistant.

This module contains helper functions that are used across different
parts of the application, such as input validation, data formatting,
or colored terminal output.
"""

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
    return True # Placeholder

def format_output(data: dict) -> str:
    """
    Formats a dictionary for clean printing to the console.
    """
    # Hint: The 'json' or 'pprint' modules can be useful for pretty-printing.
    # You could also add colors using a library like 'rich' or 'colorama'
    # to make the output more readable (e.g., green for success, red for errors).
    import json
    return json.dumps(data, indent=2)
