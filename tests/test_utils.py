# tests/test_utils.py

"""
Tests for utility functions, focusing on output formatting with various data types.
"""

import pytest
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.utils import format_output, validate_ip, Colors

class TestValidateIP:
    """Test IP address validation functionality."""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip("192.168.1.1") == True
        assert validate_ip("10.0.0.1") == True
        assert validate_ip("172.16.0.1") == True
        assert validate_ip("8.8.8.8") == True
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip("2001:db8::1") == True
        assert validate_ip("::1") == True
        assert validate_ip("fe80::1") == True
    
    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert validate_ip("256.256.256.256") == False
        assert validate_ip("192.168.1") == False
        assert validate_ip("not.an.ip") == False
        assert validate_ip("") == False

class TestFormatOutput:
    """Test output formatting for various network operation results."""
    
    def test_error_formatting(self):
        """Test error message formatting."""
        error_data = {
            "success": False,
            "error": "Connection timeout"
        }
        result = format_output(error_data)
        
        assert "❌ OPERATION FAILED" in result
        assert "Connection timeout" in result
        assert "Troubleshooting tips" in result
        assert Colors.RED in result
    
    def test_ping_output_formatting(self):
        """Test ping output formatting with RTT analysis."""
        ping_data = {
            "success": True,
            "output": """PING google.com (142.250.191.14): 56 data bytes
64 bytes from 142.250.191.14: icmp_seq=0 ttl=118 time=8.123 ms
64 bytes from 142.250.191.14: icmp_seq=1 ttl=118 time=7.456 ms
64 bytes from 142.250.191.14: icmp_seq=2 ttl=118 time=9.234 ms
64 bytes from 142.250.191.14: icmp_seq=3 ttl=118 time=8.567 ms

--- google.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
round-trip min/avg/max/stddev = 7.456/8.345/9.234/0.678 ms"""
        }
        result = format_output(ping_data)
        
        assert "🏓 PING ANALYSIS" in result
        assert "ICMP packets" in result
        assert "📡 Target:" in result
        assert "RTT Analysis:" in result
        assert "Excellent" in result  # RTT < 10ms
        assert "Perfect connectivity" in result  # 0% packet loss
    
    def test_ping_high_rtt_formatting(self):
        """Test ping formatting with high RTT values."""
        ping_data = {
            "success": True,
            "output": """PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=75.123 ms
64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=82.456 ms

--- example.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss"""
        }
        result = format_output(ping_data)
        
        assert "High (> 50ms)" in result
        assert Colors.RED in result
    
    def test_nmap_output_formatting(self):
        """Test nmap scan results formatting."""
        nmap_data = {
            "success": True,
            "output": [
                {"port": "22", "state": "open", "service": "ssh"},
                {"port": "80", "state": "open", "service": "http"},
                {"port": "443", "state": "filtered", "service": "https"}
            ]
        }
        result = format_output(nmap_data)
        
        assert "🛡️  PORT SCAN RESULTS" in result
        assert "potential entry points" in result
        assert "🔓 Port" in result and "22" in result  # Open port
        assert "🔒 Port" in result and "443" in result  # Filtered port
        assert "SSH - Ensure key-based auth" in result  # Security note
        assert "HTTP - Web server" in result
    
    def test_nmap_no_ports_formatting(self):
        """Test nmap formatting when no ports are found."""
        nmap_data = {
            "success": True,
            "output": "No open ports found among the top 10 on 192.168.1.1."
        }
        result = format_output(nmap_data)
        
        # This will be handled by generic string output since it's not a list
        assert "📋 Command Output:" in result
        assert "No open ports found" in result
    
    def test_dns_success_formatting(self):
        """Test DNS lookup success formatting."""
        dns_data = {
            "stdout": "The IP address for google.com is 142.250.191.14",
            "stderr": "",
            "exit_code": 0
        }
        result = format_output(dns_data)
        
        assert "🌐 DNS LOOKUP RESULTS" in result
        assert "translates human-readable names" in result
        assert "✅ Resolution successful" in result
        assert "properly configured" in result
        assert "142.250.191.14" in result
    
    def test_dns_error_formatting(self):
        """Test DNS lookup error formatting."""
        dns_data = {
            "stdout": "",
            "stderr": "Could not resolve host: Name or service not known",
            "exit_code": 1
        }
        result = format_output(dns_data)
        
        assert "🌐 DNS LOOKUP RESULTS" in result
        assert "❌ DNS Error" in result
        assert "Check domain spelling" in result
        assert "Name or service not known" in result
    
    def test_netstat_formatting(self):
        """Test netstat output formatting."""
        netstat_data = {
            "success": True,
            "output": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      5678/mysqld
tcp6       0      0 :::80                   :::*                    LISTEN      9012/apache2"""
        }
        result = format_output(netstat_data)
        
        assert "🔌 LOCAL PORT STATUS" in result
        assert "listening for connections" in result
        assert "📋 LISTENING SERVICES" in result
        assert "SSH - Ensure key-based auth" in result
        assert "MySQL - Database should not be public" in result
    
    def test_acl_deny_formatting(self):
        """Test ACL deny rule formatting."""
        acl_data = {
            "success": True,
            "output": "access-list 101 deny ip host 192.168.1.100 host 10.0.0.1"
        }
        result = format_output(acl_data)
        
        assert "🛡️  ACCESS CONTROL LIST" in result
        assert "control network traffic flow" in result
        assert "✅ Generated ACL Rule" in result
        assert "🚫 This rule BLOCKS traffic" in result
        assert "Apply this rule to your Cisco device" in result
    
    def test_acl_permit_formatting(self):
        """Test ACL permit rule formatting."""
        acl_data = {
            "success": True,
            "output": "access-list 101 permit ip host 192.168.1.100 host 10.0.0.1"
        }
        result = format_output(acl_data)
        
        assert "✅ This rule ALLOWS traffic" in result
        assert Colors.GREEN in result
    
    def test_generic_string_output(self):
        """Test generic string output formatting."""
        generic_data = {
            "success": True,
            "output": "Some generic command output here"
        }
        result = format_output(generic_data)
        
        assert "📋 Command Output:" in result
        assert "Some generic command output here" in result
    
    def test_structured_data_formatting(self):
        """Test structured data (dict/list) formatting."""
        structured_data = {
            "success": True,
            "output": {
                "status": "active",
                "connections": 42,
                "uptime": "5 days"
            }
        }
        result = format_output(structured_data)
        
        assert "✅ Results:" in result
        assert '"status": "active"' in result
        assert '"connections": 42' in result
    
    def test_no_output_key_formatting(self):
        """Test formatting when no output key is present."""
        no_output_data = {
            "success": True,
            "status": "completed",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        result = format_output(no_output_data)
        
        assert "✅ Operation completed successfully" in result
        assert '"status": "completed"' in result
    
    def test_non_dict_input(self):
        """Test formatting with non-dictionary input."""
        result = format_output("simple string")
        assert result == "simple string"
        
        result = format_output(42)
        assert result == "42"
    
    def test_color_codes_present(self):
        """Test that color codes are properly included in output."""
        error_data = {"success": False, "error": "Test error"}
        result = format_output(error_data)
        
        # Check that ANSI color codes are present
        assert '\033[' in result  # ANSI escape sequence
        assert Colors.RED in result
        assert Colors.END in result
    
    def test_security_notes_coverage(self):
        """Test that security notes cover common ports."""
        from src.utils import _get_port_security_notes
        
        # Test common ports have security notes
        assert "SSH" in _get_port_security_notes("22")
        assert "Telnet" in _get_port_security_notes("23")
        assert "HTTP" in _get_port_security_notes("80")
        assert "HTTPS" in _get_port_security_notes("443")
        assert "RDP" in _get_port_security_notes("3389")
        
        # Test unknown port returns empty string
        assert _get_port_security_notes("9999") == ""

if __name__ == "__main__":
    pytest.main([__file__])