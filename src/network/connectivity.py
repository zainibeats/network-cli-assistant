"""
Basic connectivity functions for network testing.

This module provides functionality for testing network connectivity using ping and traceroute.
"""

import subprocess
import logging
from ..validation.network import validate_target
from ..logging_config import log_operation


@log_operation("ping")
def ping(host: str) -> dict:
    """
    Pings a host to test network connectivity and measure response times.
    
    Args:
        host: The hostname or IP address to ping
        
    Returns:
        dict: Contains success status and ping output
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    logger = logging.getLogger("network_cli.ping")
    logger.info(f"Starting ping operation to {host}")
    
    print(f"Pinging host '{host}'...")
    command = ['ping', '-c', '4', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        
        logger.info(f"Ping completed successfully", extra={
            "packets_sent": 4,
            "exit_code": result.returncode
        })
        
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Ping operation timed out after 30 seconds")
        return {
            "success": False,
            "error": f"Ping operation timed out after 30 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            logger.error(f"DNS resolution failed for {host}")
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            logger.error(f"Network unreachable when trying to ping {host}")
            return {
                "success": False,
                "error": f"Network unreachable when trying to ping {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            logger.error(f"Permission denied for ping operation")
            return {
                "success": False,
                "error": "Permission denied for ping operation",
                "error_type": "permission_denied"
            }
        else:
            logger.error(f"Ping failed: {stderr_output}")
            return {
                "success": False,
                "error": stderr_output or f"Failed to ping {host}",
                "error_type": "ping_failed"
            }
    except FileNotFoundError:
        logger.error("Ping command not found on system")
        return {
            "success": False,
            "error": "Ping command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        logger.error(f"Unexpected error during ping: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Unexpected error during ping: {str(e)}",
            "error_type": "unexpected_error"
        }


@log_operation("traceroute")
def traceroute(host: str) -> dict:
    """
    Traces the network path to a destination, showing each router (hop) along the way.
    
    Args:
        host: The hostname or IP address to trace the route to
        
    Returns:
        dict: Contains success status and traceroute output
    """
    # Validate target parameter
    is_valid_target, error_msg, _ = validate_target(host)
    if not is_valid_target:
        return {"success": False, "error": error_msg}

    logger = logging.getLogger("network_cli.traceroute")
    logger.info(f"Starting traceroute to {host}")
    
    print(f"Tracing network path to '{host}'...")
    command = ['traceroute', host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        
        logger.info(f"Traceroute completed successfully", extra={
            "exit_code": result.returncode
        })
        
        return {
            "success": True,
            "output": result.stdout,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Traceroute operation timed out after 120 seconds")
        return {
            "success": False,
            "error": f"Traceroute operation timed out after 120 seconds",
            "error_type": "timeout"
        }
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr or ""
        
        if "Name or service not known" in stderr_output or "cannot resolve" in stderr_output.lower():
            logger.error(f"DNS resolution failed for {host}")
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}'",
                "error_type": "dns_resolution"
            }
        elif "Network is unreachable" in stderr_output:
            logger.error(f"Network unreachable when trying to traceroute to {host}")
            return {
                "success": False,
                "error": f"Network unreachable when trying to traceroute to {host}",
                "error_type": "network_unreachable"
            }
        elif "Operation not permitted" in stderr_output:
            logger.error(f"Permission denied for traceroute operation")
            return {
                "success": False,
                "error": "Permission denied for traceroute operation",
                "error_type": "permission_denied"
            }
        else:
            logger.error(f"Traceroute failed: {stderr_output}")
            return {
                "success": False,
                "error": stderr_output or f"Failed to trace route to {host}",
                "error_type": "traceroute_failed"
            }
    except FileNotFoundError:
        logger.error("Traceroute command not found on system")
        return {
            "success": False,
            "error": "Traceroute command not found",
            "error_type": "command_not_found"
        }
    except Exception as e:
        logger.error(f"Unexpected error during traceroute: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Unexpected error during traceroute: {str(e)}",
            "error_type": "unexpected_error"
        }