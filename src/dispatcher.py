# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

def parse_command(user_input: str) -> dict:
    """
    Parses natural language and maps it to a core function call.

    This is the most complex part of the application. For now, we can
    start with a very simple keyword-based approach. A more advanced
    implementation might involve regular expressions, or even a small
    NLP model.

    Args:
        user_input: The raw string from the user.

    Returns:
        A dictionary representing the function to call and its arguments.
        Returns an empty dictionary if no command could be parsed.
        Example:
        {
            "function": "run_command",
            "args": {"host": "10.1.1.1", "cmd": "show version"}
        }
    """
    # Hint: How can you identify the user's intent?
    # 1. Look for keywords (e.g., "show", "port", "status", "block", "generate acl").
    # 2. Use regular expressions to extract entities like IP addresses or hostnames.
    #
    # Example simple logic:
    # if "port status on" in user_input:
    #   # ... extract host and build the command
    # elif "block" in user_input and "from" in user_input:
    #   # ... extract IPs and build the command

    print(f"Dispatching command for: '{user_input}'")
    # This is a placeholder. You will implement the parsing logic here.
    return {}
