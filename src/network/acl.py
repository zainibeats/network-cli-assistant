"""
ACL generation functions for network configuration.

This module provides functionality for generating Cisco-style Access Control List (ACL) rules.
"""

import logging
from typing import Literal
from ..validation.network import validate_ip_with_details
from ..logging_config import log_operation


@log_operation("acl_generation")
def generate_acl(src_ip: str, dst_ip: str, action: Literal["permit", "deny"]) -> dict:
    """
    Generates a Cisco-style Access Control List (ACL) rule.

    Args:
        src_ip: The source IP address to match.
        dst_ip: The destination IP address to match.
        action: Whether to 'permit' or 'deny' the traffic.

    Returns:
        A dictionary containing the generated ACL configuration line.
    """
    # Validate source IP address
    is_valid_src, src_error, _ = validate_ip_with_details(src_ip)
    if not is_valid_src:
        return {"success": False, "error": src_error}
    
    # Validate destination IP address
    is_valid_dst, dst_error, _ = validate_ip_with_details(dst_ip)
    if not is_valid_dst:
        return {"success": False, "error": dst_error}
    
    # Validate action parameter
    if not action or action not in ["permit", "deny"]:
        return {"success": False, "error": "Action must be either 'permit' or 'deny'"}

    logger = logging.getLogger("network_cli.acl")
    logger.info(f"Generating ACL rule", extra={
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "action": action
    })
    
    print(f"Generating ACL to {action} traffic from {src_ip} to {dst_ip}...")
    acl_rule = f"access-list 101 {action} ip host {src_ip} host {dst_ip}"
    
    logger.info(f"ACL rule generated successfully", extra={
        "acl_rule": acl_rule
    })
    
    return {"success": True, "output": acl_rule}