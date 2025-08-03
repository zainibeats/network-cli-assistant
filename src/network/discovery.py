"""
Host and network discovery functions.

This module provides functionality for discovering active hosts on networks.
"""

import subprocess
import logging
import time
import ipaddress
from ..validation.network import validate_network_target
from ..logging_config import log_operation, get_logger


@log_operation("host_discovery")
def discover_hosts(network: str, max_hosts: int = 254, scan_method: str = "ping", timeout: int = 300) -> dict:
    """
    Discovers active hosts on a network with enhanced configuration options.
    
    Args:
        network (str): The network range to scan in CIDR notation (e.g., 192.168.1.0/24)
        max_hosts (int): Maximum number of hosts to scan (default: 254, max: 65534)
        scan_method (str): Discovery method - "ping", "syn", or "arp" (default: "ping")
        timeout (int): Timeout in seconds for the scan operation (default: 300, max: 3600)
        
    Returns:
        dict: Contains list of active hosts found on the network with progress information
    """
    # Validate network parameter (supports CIDR notation)
    is_valid_network, error_msg, target_type = validate_network_target(network)
    if not is_valid_network:
        return {"success": False, "error": error_msg}
    
    # Ensure it's actually a network range, not a single host
    if target_type != 'cidr':
        return {"success": False, "error": "Host discovery requires a network range in CIDR notation (e.g., 192.168.1.0/24)"}
    
    # Validate max_hosts parameter
    if not isinstance(max_hosts, int) or max_hosts < 1 or max_hosts > 65534:
        return {"success": False, "error": "max_hosts must be between 1 and 65534"}
    
    # Validate scan_method parameter
    valid_methods = ["ping", "syn", "arp"]
    if scan_method not in valid_methods:
        return {"success": False, "error": f"scan_method must be one of: {', '.join(valid_methods)}"}
    
    # Validate timeout parameter
    if not isinstance(timeout, int) or timeout < 10 or timeout > 3600:
        return {"success": False, "error": "Timeout must be between 10 and 3600 seconds"}
    
    logger = logging.getLogger("network_cli.host_discovery")
    
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        total_hosts = network_obj.num_addresses - 2  # Exclude network and broadcast
        
        # Limit the scan to max_hosts or total available hosts, whichever is smaller
        hosts_to_scan = min(max_hosts, total_hosts)
        
        # Calculate estimated time based on scan method and host count
        if scan_method == "ping":
            estimated_time = hosts_to_scan * 0.5  # Ping is fastest
        elif scan_method == "syn":
            estimated_time = hosts_to_scan * 1.0  # SYN scan is moderate
        else:  # arp
            estimated_time = hosts_to_scan * 0.3  # ARP is very fast on local networks
        
        logger.info(f"Starting host discovery on {network}", extra={
            "network": network,
            "max_hosts": max_hosts,
            "hosts_to_scan": hosts_to_scan,
            "scan_method": scan_method,
            "timeout": timeout,
            "estimated_time": estimated_time
        })
        
        print(f"Discovering active hosts on network {network}...")
        print(f"Scanning up to {hosts_to_scan} hosts using {scan_method} method...")
        if estimated_time > 30:
            print(f"This scan may take up to {int(estimated_time)} seconds. Please wait...")
        
        # Build nmap command based on scan method
        cmd = ["nmap", "-T4"]
        
        if scan_method == "ping":
            cmd.extend(["-sn"])  # Ping scan only, no port scan
        elif scan_method == "syn":
            cmd.extend(["-sS", "--top-ports", "1"])  # SYN scan with top port
        elif scan_method == "arp":
            cmd.extend(["-PR", "-sn"])  # ARP ping scan
        
        # Add timeout and output options
        cmd.extend([
            "--host-timeout", f"{min(timeout // hosts_to_scan, 30)}s",  # Per-host timeout
            "--max-rtt-timeout", "2s",
            "-oG", "-",  # Greppable output for easier parsing
        ])
        
        # Get list of hosts to scan
        host_list = list(network_obj.hosts())[:hosts_to_scan]
        
        # For large scans, process in batches to provide progress updates
        batch_size = min(50, hosts_to_scan)
        active_hosts = []
        processed_hosts = 0
        start_time = time.time()
        
        for i in range(0, len(host_list), batch_size):
            batch = host_list[i:i + batch_size]
            batch_targets = [str(ip) for ip in batch]
            
            # Create command for this batch
            batch_cmd = cmd + batch_targets
            
            try:
                result = subprocess.run(batch_cmd, capture_output=True, text=True, check=True, timeout=timeout)
                
                # Parse greppable output for this batch
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Host:') and 'Status: Up' in line:
                        # Extract IP address from the line
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            if ip not in active_hosts:
                                active_hosts.append(ip)
                
                processed_hosts += len(batch)
                
                # Show progress for large scans
                if hosts_to_scan > 20 and processed_hosts % 20 == 0:
                    elapsed = time.time() - start_time
                    progress = (processed_hosts / hosts_to_scan) * 100
                    print(f"Progress: {processed_hosts}/{hosts_to_scan} hosts scanned ({progress:.1f}%) - {len(active_hosts)} active hosts found")
                        
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                # Log the error but continue with next batch
                logger.warning(f"Batch scan failed for hosts {i}-{i+len(batch)}: {e}")
                processed_hosts += len(batch)
                continue
        
        # Remove duplicates while preserving order
        unique_hosts = []
        seen = set()
        for host in active_hosts:
            if host not in seen:
                unique_hosts.append(host)
                seen.add(host)
        
        elapsed_time = time.time() - start_time
        
        logger.info(f"Host discovery completed: found {len(unique_hosts)} active hosts", extra={
            "active_hosts": unique_hosts,
            "hosts_scanned": processed_hosts,
            "scan_time": elapsed_time,
            "scan_method": scan_method
        })
        
        results = {
            "success": True,
            "network": network,
            "active_hosts": unique_hosts,
            "total_hosts_found": len(unique_hosts),
            "hosts_scanned": processed_hosts,
            "scan_method": scan_method,
            "scan_time": round(elapsed_time, 2),
            "scan_type": "host_discovery"
        }
        
        if unique_hosts:
            results["output"] = f"Found {len(unique_hosts)} active hosts on {network} (scanned {processed_hosts} hosts in {elapsed_time:.1f}s):\n"
            results["output"] += "\n".join(f"  • {host}" for host in unique_hosts)
            results["output"] += f"\n\nScan method: {scan_method.upper()}"
            if processed_hosts < total_hosts:
                results["output"] += f"\nNote: Scanned {processed_hosts} of {total_hosts} total hosts in the network."
        else:
            results["output"] = f"No active hosts found in {network} (scanned {processed_hosts} hosts in {elapsed_time:.1f}s)."
            results["output"] += f"\nScan method: {scan_method.upper()}"
            results["output"] += f"\nNetwork may be down, heavily firewalled, or hosts may not respond to {scan_method} probes."
        
        # Log the scan result
        get_logger().log_network_scan(network, "host_discovery", results)
        
        return results
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Host discovery failed: {e.stderr or str(e)}")
        return {
            "success": False, 
            "error": e.stderr or str(e),
            "error_type": "nmap_failed"
        }
    except FileNotFoundError:
        logger.error("Nmap command not found on system")
        return {
            "success": False,
            "error": "Nmap command not found",
            "error_type": "command_not_found"
        }
    except Exception as ex:
        logger.error(f"Unexpected error during host discovery: {str(ex)}", exc_info=True)
        return {
            "success": False, 
            "error": str(ex),
            "error_type": "unexpected_error"
        }