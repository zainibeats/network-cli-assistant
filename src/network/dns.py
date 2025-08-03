"""
DNS lookup functions for network name resolution.

This module provides functionality for performing DNS lookups including forward and reverse resolution.
"""

import socket
import logging
from ..validation.network import validate_target, validate_ip
from ..logging_config import log_operation


@log_operation("dns_lookup")
def dns_lookup(host: str) -> dict:
    """
    Performs comprehensive DNS lookups including forward and reverse resolution.
    
    Args:
        host: The hostname or IP address to look up
        
    Returns:
        dict: Contains forward/reverse lookup results
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}
    
    logger = logging.getLogger("network_cli.dns")
    logger.info(f"Starting DNS lookup for {host}")
    
    print(f"Performing DNS lookup for '{host}'...")
    
    results = {
        "success": True,
        "forward_lookup": None,
        "reverse_lookup": None
    }
    
    # Determine if input is an IP address or hostname
    is_ip_address = validate_ip(host)
    logger.debug(f"Input type detected: {'IP address' if is_ip_address else 'hostname'}")
    
    try:
        if is_ip_address:
            # Input is IP address - do reverse lookup first, then forward lookup of result
            print(f"Input detected as IP address, performing reverse lookup...")
            try:
                hostname = socket.gethostbyaddr(host)[0]
                logger.info(f"Reverse lookup successful: {host} -> {hostname}")
                results["reverse_lookup"] = {
                    "success": True,
                    "ip_address": host,
                    "hostname": hostname
                }
                
                # Now do forward lookup of the resolved hostname
                try:
                    forward_ip = socket.gethostbyname(hostname)
                    logger.info(f"Forward lookup successful: {hostname} -> {forward_ip}")
                    results["forward_lookup"] = {
                        "success": True,
                        "hostname": hostname,
                        "ip_address": forward_ip,
                        "consistency_check": forward_ip == host
                    }
                    if forward_ip != host:
                        logger.warning(f"DNS consistency issue: forward lookup returned {forward_ip}, original was {host}")
                        results["forward_lookup"]["warning"] = f"Forward lookup returned different IP ({forward_ip}) than original ({host})"
                except socket.gaierror:
                    logger.warning(f"Forward lookup failed for resolved hostname {hostname}")
                    results["forward_lookup"] = {
                        "success": False,
                        "error": f"Could not perform forward lookup for resolved hostname {hostname}"
                    }
                    
            except (socket.gaierror, socket.herror) as e:
                logger.error(f"Reverse lookup failed for {host}: {e}")
                results["reverse_lookup"] = {
                    "success": False,
                    "ip_address": host,
                    "error": f"Could not perform reverse lookup: {e}"
                }
                results["success"] = False
                
        else:
            # Input is hostname - do forward lookup first, then reverse lookup of result
            print(f"Input detected as hostname, performing forward lookup...")
            try:
                ip_address = socket.gethostbyname(host)
                logger.info(f"Forward lookup successful: {host} -> {ip_address}")
                results["forward_lookup"] = {
                    "success": True,
                    "hostname": host,
                    "ip_address": ip_address
                }
                
                # Now do reverse lookup of the resolved IP
                try:
                    reverse_hostname = socket.gethostbyaddr(ip_address)[0]
                    logger.info(f"Reverse lookup successful: {ip_address} -> {reverse_hostname}")
                    results["reverse_lookup"] = {
                        "success": True,
                        "ip_address": ip_address,
                        "hostname": reverse_hostname,
                        "consistency_check": reverse_hostname.lower() == host.lower()
                    }
                    if reverse_hostname.lower() != host.lower():
                        logger.warning(f"DNS consistency issue: reverse lookup returned {reverse_hostname}, original was {host}")
                        results["reverse_lookup"]["note"] = f"Reverse lookup returned different hostname ({reverse_hostname}) than original ({host})"
                except (socket.gaierror, socket.herror):
                    logger.warning(f"Reverse lookup failed for {ip_address}")
                    results["reverse_lookup"] = {
                        "success": False,
                        "ip_address": ip_address,
                        "error": "Could not perform reverse lookup"
                    }
                    
            except socket.gaierror as e:
                logger.error(f"Forward lookup failed for {host}: {e}")
                results["forward_lookup"] = {
                    "success": False,
                    "hostname": host,
                    "error": f"Could not resolve hostname: {e}"
                }
                results["success"] = False
    
    except Exception as e:
        logger.error(f"DNS lookup failed: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"DNS lookup failed: {str(e)}",
            "error_type": "dns_lookup_failed"
        }
    
    # Format for backward compatibility with existing code expecting stdout/stderr format
    if results["success"]:
        summary_parts = []
        if results["forward_lookup"] and results["forward_lookup"]["success"]:
            fl = results["forward_lookup"]
            summary_parts.append(f"Forward: {fl['hostname']} → {fl['ip_address']}")
        if results["reverse_lookup"] and results["reverse_lookup"]["success"]:
            rl = results["reverse_lookup"]
            summary_parts.append(f"Reverse: {rl['ip_address']} → {rl['hostname']}")
        
        results["stdout"] = "; ".join(summary_parts) if summary_parts else "DNS lookup completed"
        results["stderr"] = ""
        results["exit_code"] = 0
    else:
        error_parts = []
        if results["forward_lookup"] and not results["forward_lookup"]["success"]:
            error_parts.append(results["forward_lookup"]["error"])
        if results["reverse_lookup"] and not results["reverse_lookup"]["success"]:
            error_parts.append(results["reverse_lookup"]["error"])
        
        results["stdout"] = ""
        results["stderr"] = "; ".join(error_parts) if error_parts else "DNS lookup failed"
        results["exit_code"] = 1
    
    return results