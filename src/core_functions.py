# src/core_functions.py

"""
Core networking functions that the AI assistant can execute.

Each function in this module represents a distinct capability,
like running a command on a remote host or generating a configuration snippet.
"""

from typing import Literal

def run_command(host: str, cmd: str) -> dict:
    """
    Connects to a remote host via SSH and executes a shell command.

    Args:
        host: The hostname or IP address of the target server.
        cmd: The command to execute on the remote server.

    Returns:
        A dictionary containing the command's output, errors, and exit code.
        For example:
        {
            "stdout": "...",
            "stderr": "...",
            "exit_code": 0
        }
    """
    # Hint: The 'paramiko' or 'fabric' library is excellent for SSH operations.
    # You'll need to handle:
    # 1. Establishing an SSH connection.
    # 2. Executing the command.
    # 3. Capturing stdout, stderr, and the exit code.
    # 4. Closing the connection.
    # Remember to handle potential exceptions, like connection errors!
    print(f"Executing '{cmd}' on host '{host}'...")
    # This is a placeholder. You will implement the actual SSH logic here.
    return {"stdout": "Command output from host", "stderr": "", "exit_code": 0}

def generate_acl(src_ip: str, dst_ip: str, action: Literal["permit", "deny"]) -> dict:
    """
    Generates a Cisco-style Access Control List (ACL) rule.

    Args:
        src_ip: The source IP address to match.
        dst_ip: The destination IP address to match.
        action: Whether to 'permit' or 'deny' the traffic.

    Returns:
        A dictionary containing the generated ACL configuration line.
        For example:
        {
            "acl_rule": "access-list 101 deny ip host 203.0.113.45 host 192.0.2.10"
        }
    """
    # Hint: This function is about string formatting.
    # You'll construct the ACL string based on the inputs.
    # Consider how you might validate the IP addresses to ensure they are valid.
    # The 'ipaddress' module in the standard library is perfect for this.
    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    # This is a placeholder. You will implement the string generation here.
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    return {"acl_rule": acl_rule}

# Future idea: What other functions could go here?
# - ping(host: str) -> dict
# - traceroute(host: str) -> dict
# - check_dns(domain: str) -> dict
