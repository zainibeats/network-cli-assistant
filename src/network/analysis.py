"""
Result analysis and interpretation functions for network operations.

This module provides functionality for analyzing and interpreting network scan results.
"""


def interpret_nmap_results(scan_results: dict) -> dict:
    """
    Interpret nmap scan results and provide comprehensive security analysis.
    
    Args:
        scan_results: The results from run_nmap_scan function
        
    Returns:
        dict: Comprehensive analysis with security implications and recommendations
    """
    if not scan_results.get("success"):
        return {
            "overall_risk": "unknown",
            "summary": "Scan failed",
            "recommendations": ["Verify target is reachable", "Check firewall settings", "Ensure nmap has proper permissions"]
        }
    
    if not scan_results.get("ports_found"):
        return {
            "overall_risk": "minimal",
            "summary": "No open ports found - system appears well secured",
            "recommendations": ["Verify target is reachable", "System may have strong firewall protection"]
        }
    
    ports_found = scan_results["ports_found"]
    host_info = scan_results.get("host_info", {})
    
    # Analyze risk levels
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    critical_services = []
    high_risk_services = []
    open_ports = []
    
    for port_info in ports_found:
        if port_info["state"] == "open":
            open_ports.append(port_info["port"])
            risk_level = port_info["security_risk"]
            risk_counts[risk_level] += 1
            
            if risk_level == "critical":
                critical_services.append(f"Port {port_info['port']} ({port_info['service']})")
            elif risk_level == "high":
                high_risk_services.append(f"Port {port_info['port']} ({port_info['service']})")
    
    # Determine overall risk
    if risk_counts["critical"] > 0:
        overall_risk = "critical"
    elif risk_counts["high"] > 0:
        overall_risk = "high"
    elif risk_counts["medium"] > 0:
        overall_risk = "medium"
    elif risk_counts["low"] > 0:
        overall_risk = "low"
    else:
        overall_risk = "minimal"
    
    # Generate summary
    total_open = len(open_ports)
    target = host_info.get("ip", "target")
    
    summary_parts = [
        f"Scanned {target} and found {total_open} open port{'s' if total_open != 1 else ''}"
    ]
    
    if risk_counts["critical"] > 0:
        summary_parts.append(f"{risk_counts['critical']} CRITICAL risk service{'s' if risk_counts['critical'] != 1 else ''}")
    if risk_counts["high"] > 0:
        summary_parts.append(f"{risk_counts['high']} high risk service{'s' if risk_counts['high'] != 1 else ''}")
    if risk_counts["medium"] > 0:
        summary_parts.append(f"{risk_counts['medium']} medium risk service{'s' if risk_counts['medium'] != 1 else ''}")
    
    summary = ". ".join(summary_parts) + "."
    
    # Generate recommendations
    recommendations = []
    
    if critical_services:
        recommendations.append("IMMEDIATE ACTION REQUIRED:")
        for service in critical_services:
            recommendations.append(f"  • {service} - Extremely high security risk")
        recommendations.append("  • Block these services at firewall level immediately")
        recommendations.append("  • Review if these services are actually needed")
    
    if high_risk_services:
        recommendations.append("HIGH PRIORITY:")
        for service in high_risk_services:
            recommendations.append(f"  • {service} - Requires immediate security review")
        recommendations.append("  • Implement strong authentication and encryption")
        recommendations.append("  • Restrict access to authorized networks only")
    
    # General recommendations based on findings
    if total_open > 10:
        recommendations.append("GENERAL: Large number of open ports detected - review if all services are necessary")
    
    if any(port in ["22", "3389"] for port in open_ports):
        recommendations.append("REMOTE ACCESS: SSH/RDP detected - ensure strong authentication is enabled")
    
    if any(port in ["80", "443", "8080", "8443"] for port in open_ports):
        recommendations.append("WEB SERVICES: Web servers detected - ensure they are properly secured and updated")
    
    if any(port in ["1433", "3306", "5432", "6379", "27017"] for port in open_ports):
        recommendations.append("DATABASES: Database services exposed - these should NEVER be accessible from internet")
    
    # Add follow-up suggestions
    recommendations.extend([
        "NEXT STEPS:",
        "  • Run detailed vulnerability scan with nmap scripts (-sC -sV)",
        "  • Check for default credentials on discovered services",
        "  • Review firewall rules and network segmentation",
        "  • Monitor these services for suspicious activity"
    ])
    
    return {
        "overall_risk": overall_risk,
        "summary": summary,
        "risk_breakdown": risk_counts,
        "critical_services": critical_services,
        "high_risk_services": high_risk_services,
        "total_open_ports": total_open,
        "recommendations": recommendations,
        "target_info": host_info
    }