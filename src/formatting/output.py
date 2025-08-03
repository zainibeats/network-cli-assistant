"""
Output formatting and display functions.

This module provides functions for formatting network operation results
into human-readable output with colors and structure.
"""

import json
from .colors import Colors


def format_output(data: dict) -> str:
    """
    Formats a dictionary for clean, human-readable printing to the console.
    
    Args:
        data: Dictionary containing operation results
        
    Returns:
        Formatted string with colors and basic structure
    """
    if not isinstance(data, dict):
        return str(data)

    # Handle error cases with basic formatting
    if data.get("success") is False:
        error_message = data.get("error", "An unknown error occurred.")
        formatted_lines = []
        formatted_lines.append(f"{Colors.RED}{Colors.BOLD}❌ OPERATION FAILED{Colors.END}")
        formatted_lines.append(f"{Colors.RED}Error: {error_message}{Colors.END}")
        
        # Add error type if available
        if "error_type" in data:
            formatted_lines.append(f"{Colors.YELLOW}Type: {data['error_type']}{Colors.END}")
        
        return '\n'.join(formatted_lines)

    # Special handling for nmap results with interpretation
    if "interpretation" in data and "ports_found" in data:
        return _format_nmap_output(data)

    # Handle successful outputs
    output = data.get("output")
    
    if output is None:
        # Handle cases where there's no specific 'output' key
        clean_data = {k: v for k, v in data.items() if k not in ["success"]}
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        
        if clean_data:
            formatted_lines.append(json.dumps(clean_data, indent=2))
        
        return '\n'.join(formatted_lines)

    # Format based on output type
    if isinstance(output, str):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Output:{Colors.END}")
        formatted_lines.append(output)
        
        return '\n'.join(formatted_lines)
    
    # Handle other structured data
    elif isinstance(output, (dict, list)):
        formatted_lines = [f"{Colors.GREEN}✅ Operation completed successfully{Colors.END}"]
        formatted_lines.append(f"\n{Colors.BOLD}Results:{Colors.END}")
        formatted_lines.append(json.dumps(output, indent=2))
        return '\n'.join(formatted_lines)
        
    return str(output)


def _format_nmap_output(data: dict) -> str:
    """
    Formats nmap scan results with interpretation and security analysis.
    
    Args:
        data: Dictionary containing nmap scan results with interpretation
        
    Returns:
        Formatted string with security analysis and recommendations
    """
    formatted_lines = []
    interpretation = data.get("interpretation", {})
    ports_found = data.get("ports_found", [])
    host_info = data.get("host_info", {})
    
    # Check if this is a network scan with multiple hosts
    network_summary = data.get("network_summary")
    hosts_with_ports = data.get("hosts_with_ports", [])
    
    # Header with overall risk assessment
    overall_risk = interpretation.get("overall_risk", "unknown")
    risk_colors = {
        "critical": Colors.RED + Colors.BOLD,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.GREEN,
        "minimal": Colors.GREEN,
        "unknown": Colors.WHITE
    }
    
    risk_color = risk_colors.get(overall_risk, Colors.WHITE)
    formatted_lines.append(f"{Colors.GREEN}✅ Nmap scan completed{Colors.END}")
    formatted_lines.append(f"{Colors.BOLD}Security Risk Level: {risk_color}{overall_risk.upper()}{Colors.END}")
    
    # For network scans, show the network summary first
    if network_summary and len(hosts_with_ports) > 1:
        formatted_lines.append(f"\n{Colors.BOLD}Network Scan Results:{Colors.END}")
        formatted_lines.append(network_summary)
    
    # Summary
    summary = interpretation.get("summary", "Scan completed")
    formatted_lines.append(f"\n{Colors.BOLD}Summary:{Colors.END}")
    formatted_lines.append(f"{summary}")
    
    # Target information
    if host_info:
        formatted_lines.append(f"\n{Colors.BOLD}Target Information:{Colors.END}")
        if "ip" in host_info:
            formatted_lines.append(f"  IP Address: {host_info['ip']}")
        if "hostname" in host_info:
            formatted_lines.append(f"  Hostname: {host_info['hostname']}")
        if "status" in host_info:
            formatted_lines.append(f"  Status: {host_info['status']}")
    
    # Port details with security assessment
    if ports_found:
        formatted_lines.append(f"\n{Colors.BOLD}Open Ports and Security Assessment:{Colors.END}")
        
        # Consolidate ports by port number and base service name to avoid duplicates
        unique_ports = {}
        for port_info in ports_found:
            if port_info["state"] == "open":
                port = port_info["port"]
                service = port_info["service"]
                
                # Extract base service name (before any parentheses for product/version info)
                base_service = service.split('(')[0].strip()
                key = f"{port}_{base_service}"
                
                if key not in unique_ports:
                    # Use the base service name for display consistency
                    consolidated_port_info = port_info.copy()
                    consolidated_port_info["service"] = base_service
                    unique_ports[key] = consolidated_port_info
        
        # Display each unique port/service combination once
        for port_info in unique_ports.values():
            port = port_info["port"]
            service = port_info["service"]
            risk = port_info["security_risk"]
            
            # Color code by risk level
            port_color = risk_colors.get(risk, Colors.WHITE)
            formatted_lines.append(f"  {port_color}Port {port} ({service}) - {risk.upper()} RISK{Colors.END}")
            
            # Add specific recommendations for this port
            recommendations = port_info.get("recommendations", [])
            if recommendations:
                for rec in recommendations[:2]:  # Show first 2 recommendations
                    formatted_lines.append(f"    • {rec}")
                if len(recommendations) > 2:
                    formatted_lines.append(f"    • ... and {len(recommendations) - 2} more recommendations")
    
    # Overall recommendations
    recommendations = interpretation.get("recommendations", [])
    if recommendations:
        formatted_lines.append(f"\n{Colors.BOLD}Security Recommendations:{Colors.END}")
        
        current_section = None
        for rec in recommendations:
            if rec.endswith(":"):
                # This is a section header
                current_section = rec
                if "IMMEDIATE" in rec or "CRITICAL" in rec:
                    formatted_lines.append(f"{Colors.RED}{Colors.BOLD}{rec}{Colors.END}")
                elif "HIGH PRIORITY" in rec:
                    formatted_lines.append(f"{Colors.YELLOW}{Colors.BOLD}{rec}{Colors.END}")
                else:
                    formatted_lines.append(f"{Colors.CYAN}{Colors.BOLD}{rec}{Colors.END}")
            else:
                # This is a recommendation item
                if rec.startswith("  •"):
                    # Indented item
                    if current_section and ("IMMEDIATE" in current_section or "CRITICAL" in current_section):
                        formatted_lines.append(f"{Colors.RED}{rec}{Colors.END}")
                    elif current_section and "HIGH PRIORITY" in current_section:
                        formatted_lines.append(f"{Colors.YELLOW}{rec}{Colors.END}")
                    else:
                        formatted_lines.append(f"{rec}")
                else:
                    formatted_lines.append(f"{rec}")
    
    # Risk breakdown summary
    risk_breakdown = interpretation.get("risk_breakdown", {})
    if any(count > 0 for count in risk_breakdown.values()):
        formatted_lines.append(f"\n{Colors.BOLD}Risk Breakdown:{Colors.END}")
        for risk_level, count in risk_breakdown.items():
            if count > 0:
                color = risk_colors.get(risk_level, Colors.WHITE)
                formatted_lines.append(f"  {color}{risk_level.capitalize()}: {count} service{'s' if count != 1 else ''}{Colors.END}")
    
    return '\n'.join(formatted_lines)