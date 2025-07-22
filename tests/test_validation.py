# tests/test_validation.py

"""
Comprehensive tests for input validation and error handling.

Tests cover edge cases, common user errors, and validation functions
to ensure robust error handling and helpful user guidance.
"""

import pytest
from src.utils import (
    validate_ip_with_details, validate_hostname, validate_target, validate_port,
    create_validation_error, handle_network_timeout, handle_dns_resolution_error,
    handle_connection_refused_error, handle_permission_denied_error,
    handle_command_not_found_error, validate_network_operation_input
)


class TestIPValidation:
    """Test IP address validation with detailed error messages."""
    
    def test_valid_ipv4_addresses(self):
        """Test valid IPv4 addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1", 
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255"
        ]
        
        for ip in valid_ips:
            is_valid, error, suggestion = validate_ip_with_details(ip)
            assert is_valid, f"IP {ip} should be valid but got error: {error}"
            assert error is None
    
    def test_valid_ipv6_addresses(self):
        """Test valid IPv6 addresses."""
        valid_ips = [
            "2001:db8::1",
            "::1",
            "fe80::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::"
        ]
        
        for ip in valid_ips:
            is_valid, error, suggestion = validate_ip_with_details(ip)
            assert is_valid, f"IPv6 {ip} should be valid but got error: {error}"
            assert error is None
    
    def test_invalid_ipv4_addresses(self):
        """Test invalid IPv4 addresses with specific error messages."""
        invalid_cases = [
            ("192.168.1.256", "must be 0-255"),
            ("192.168.1", "Invalid IP address format"),
            ("192.168.1.1.1", "Invalid IP address format"),
            ("192.168.a.1", "not a number"),
            ("", "IP address cannot be empty"),
            ("   ", "IP address cannot be empty"),
            ("192.168.-1.1", "not a number"),
            ("999.999.999.999", "must be 0-255")
        ]
        
        for ip, expected_error_part in invalid_cases:
            is_valid, error, suggestion = validate_ip_with_details(ip)
            assert not is_valid, f"IP {ip} should be invalid"
            assert error is not None
            assert expected_error_part.lower() in error.lower(), f"Expected '{expected_error_part}' in error '{error}' for IP '{ip}'"
            assert suggestion is not None
    
    def test_special_ip_addresses(self):
        """Test special IP addresses with informational notes."""
        special_cases = [
            ("127.0.0.1", "loopback"),
            ("192.168.1.1", "private"),
            ("10.0.0.1", "private"),
            ("172.16.0.1", "private"),
            ("224.0.0.1", "multicast")
        ]
        
        for ip, expected_note in special_cases:
            is_valid, error, suggestion = validate_ip_with_details(ip)
            assert is_valid, f"IP {ip} should be valid"
            assert suggestion is not None
            assert expected_note.lower() in suggestion.lower()
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        edge_cases = [
            None,
            123,
            [],
            {},
            "not.an.ip.address"
        ]
        
        for case in edge_cases:
            is_valid, error, suggestion = validate_ip_with_details(case)
            assert not is_valid
            assert error is not None
            assert suggestion is not None


class TestHostnameValidation:
    """Test hostname validation with detailed error messages."""
    
    def test_valid_hostnames(self):
        """Test valid hostnames."""
        valid_hostnames = [
            "google.com",
            "example.org",
            "test-server.local",
            "my-server.company.com",
            "server1.domain.co.uk",
            "localhost",
            "a.bb",  # Changed from "a.b" to have valid TLD length
            "test123.example.net"
        ]
        
        for hostname in valid_hostnames:
            is_valid, error, suggestion = validate_hostname(hostname)
            assert is_valid, f"Hostname {hostname} should be valid but got error: {error}"
            assert error is None
    
    def test_invalid_hostnames(self):
        """Test invalid hostnames with specific error messages."""
        invalid_cases = [
            ("", "cannot be empty"),
            ("   ", "cannot be empty"),
            ("-example.com", "cannot start or end with a hyphen"),
            ("example.com-", "cannot start or end with a hyphen"),
            (".example.com", "cannot start or end with a dot"),
            ("example.com.", "cannot start or end with a dot"),
            ("ex..ample.com", "consecutive dots"),
            ("ex--ample.com", "consecutive hyphens"),
            ("example.123", "Top-level domain cannot be all numbers"),
            ("example.c", "Top-level domain too short"),
            ("a" * 254, "too long"),
            ("example@.com", "Invalid characters"),
            ("example$.com", "Invalid characters")
        ]
        
        for hostname, expected_error_part in invalid_cases:
            is_valid, error, suggestion = validate_hostname(hostname)
            assert not is_valid, f"Hostname {hostname} should be invalid"
            assert error is not None
            assert expected_error_part.lower() in error.lower(), f"Expected '{expected_error_part}' in error '{error}' for hostname '{hostname}'"
            assert suggestion is not None
    
    def test_common_typos(self):
        """Test common hostname typos with suggestions."""
        typo_cases = [
            ("google.co", "Did you mean .com?"),
            ("example.cm", "Did you mean .com?"),
            ("test.og", "Did you mean .org?"),
            ("site.nte", "Did you mean .net?")
        ]
        
        for hostname, expected_suggestion in typo_cases:
            is_valid, error, suggestion = validate_hostname(hostname)
            assert is_valid  # These are technically valid, just potentially typos
            assert suggestion is not None
            assert expected_suggestion in suggestion
    
    def test_local_hostnames(self):
        """Test local hostnames (single labels)."""
        local_hostnames = ["localhost", "server", "mycomputer"]
        
        for hostname in local_hostnames:
            is_valid, error, suggestion = validate_hostname(hostname)
            assert is_valid
            assert "local hostname" in suggestion.lower()


class TestPortValidation:
    """Test port number validation."""
    
    def test_valid_ports(self):
        """Test valid port numbers."""
        valid_ports = [1, 22, 80, 443, 8080, 65535, "22", "443"]
        
        for port in valid_ports:
            is_valid, error, suggestion = validate_port(port)
            assert is_valid, f"Port {port} should be valid but got error: {error}"
            assert error is None
    
    def test_invalid_ports(self):
        """Test invalid port numbers."""
        invalid_cases = [
            (0, "too low"),
            (-1, "too low"),
            (65536, "too high"),
            (99999, "too high"),
            ("abc", "Invalid port format"),
            ("", "Invalid port format"),
            (None, "Port cannot be empty"),
            ([], "Invalid port format")
        ]
        
        for port, expected_error_part in invalid_cases:
            is_valid, error, suggestion = validate_port(port)
            assert not is_valid, f"Port {port} should be invalid"
            assert error is not None
            assert expected_error_part.lower() in error.lower()
            assert suggestion is not None
    
    def test_privileged_ports(self):
        """Test privileged ports (< 1024) have appropriate warnings."""
        privileged_ports = [22, 80, 443, 993]
        
        for port in privileged_ports:
            is_valid, error, suggestion = validate_port(port)
            assert is_valid
            assert suggestion is not None
            assert "privileged port" in suggestion.lower()
    
    def test_common_ports(self):
        """Test common ports have service descriptions."""
        common_ports = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3389: "RDP"
        }
        
        for port, service in common_ports.items():
            is_valid, error, suggestion = validate_port(port)
            assert is_valid
            assert suggestion is not None
            assert service in suggestion


class TestTargetValidation:
    """Test combined IP/hostname validation."""
    
    def test_valid_targets(self):
        """Test valid targets (IPs and hostnames)."""
        valid_targets = [
            "192.168.1.1",
            "google.com",
            "localhost",
            "2001:db8::1",
            "test-server.local"
        ]
        
        for target in valid_targets:
            is_valid, error, suggestion = validate_target(target)
            assert is_valid, f"Target {target} should be valid but got error: {error}"
            assert error is None
    
    def test_invalid_targets(self):
        """Test invalid targets."""
        invalid_targets = [
            "",
            "   ",
            "192.168.1.256",
            "invalid..hostname",
            None,
            123
        ]
        
        for target in invalid_targets:
            is_valid, error, suggestion = validate_target(target)
            assert not is_valid, f"Target {target} should be invalid"
            assert error is not None
            assert suggestion is not None


class TestErrorHandlers:
    """Test error handling functions."""
    
    def test_validation_error_creation(self):
        """Test validation error response creation."""
        error = create_validation_error("IP address", "192.168.1.256", "Invalid IP", "Use valid IP format")
        
        assert error["success"] is False
        assert "Invalid IP address" in error["error"]
        assert error["field"] == "IP address"
        assert error["invalid_value"] == "192.168.1.256"
        assert error["validation_details"]["message"] == "Invalid IP"
        assert error["validation_details"]["suggestion"] == "Use valid IP format"
        assert "examples" in error["validation_details"]
    
    def test_network_timeout_error(self):
        """Test network timeout error handling."""
        error = handle_network_timeout("ping", "google.com", 30)
        
        assert error["success"] is False
        assert "timed out" in error["error"]
        assert error["target"] == "google.com"
        assert error["error_type"] == "network_timeout"
        assert "troubleshooting" in error
        assert "possible_causes" in error["troubleshooting"]
        assert "suggested_actions" in error["troubleshooting"]
        assert "next_steps" in error["troubleshooting"]
    
    def test_dns_resolution_error(self):
        """Test DNS resolution error handling."""
        error = handle_dns_resolution_error("nonexistent.domain.invalid")
        
        assert error["success"] is False
        assert "DNS resolution failed" in error["error"]
        assert error["hostname"] == "nonexistent.domain.invalid"
        assert error["error_type"] == "dns_resolution"
        assert "troubleshooting" in error
        assert "common_mistakes" in error["troubleshooting"]
    
    def test_connection_refused_error(self):
        """Test connection refused error handling."""
        error = handle_connection_refused_error("example.com", 22, "SSH")
        
        assert error["success"] is False
        assert "Connection refused" in error["error"]
        assert error["target"] == "example.com"
        assert error["port"] == 22
        assert error["service"] == "SSH"
        assert error["error_type"] == "connection_refused"
        assert "troubleshooting" in error
    
    def test_permission_denied_error(self):
        """Test permission denied error handling."""
        error = handle_permission_denied_error("ping operation")
        
        assert error["success"] is False
        assert "Permission denied" in error["error"]
        assert error["error_type"] == "permission_denied"
        assert "troubleshooting" in error
        assert "security_note" in error["troubleshooting"]
    
    def test_command_not_found_error(self):
        """Test command not found error handling."""
        error = handle_command_not_found_error("nonexistent-command", ["alternative1", "alternative2"])
        
        assert error["success"] is False
        assert "not found" in error["error"]
        assert error["error_type"] == "command_not_found"
        assert error["missing_command"] == "nonexistent-command"
        assert "alternatives" in error["troubleshooting"]
        assert "alternative1" in error["troubleshooting"]["alternatives"]


class TestNetworkOperationValidation:
    """Test comprehensive network operation validation."""
    
    def test_valid_ping_operation(self):
        """Test valid ping operation validation."""
        is_valid, error = validate_network_operation_input("ping", host="google.com")
        assert is_valid
        assert error is None
    
    def test_invalid_ping_operation(self):
        """Test invalid ping operation validation."""
        is_valid, error = validate_network_operation_input("ping", host="192.168.1.256")
        assert not is_valid
        assert error is not None
        assert error["success"] is False
        assert "Invalid target host" in error["error"]
    
    def test_valid_acl_generation(self):
        """Test valid ACL generation validation."""
        is_valid, error = validate_network_operation_input(
            "generate_acl", 
            src_ip="192.168.1.1", 
            dst_ip="10.0.0.1", 
            action="deny"
        )
        assert is_valid
        assert error is None
    
    def test_invalid_acl_generation(self):
        """Test invalid ACL generation validation."""
        # Invalid source IP
        is_valid, error = validate_network_operation_input(
            "generate_acl", 
            src_ip="invalid.ip", 
            dst_ip="10.0.0.1", 
            action="deny"
        )
        assert not is_valid
        assert error is not None
        assert "Invalid source IP" in error["error"]
        
        # Invalid action
        is_valid, error = validate_network_operation_input(
            "generate_acl", 
            src_ip="192.168.1.1", 
            dst_ip="10.0.0.1", 
            action="invalid_action"
        )
        assert not is_valid
        assert error is not None
        assert "Invalid action" in error["error"]
    
    def test_command_validation(self):
        """Test command validation for run_command operation."""
        # Valid command
        is_valid, error = validate_network_operation_input("run_command", host="server.com", cmd="ls -la")
        assert is_valid
        assert error is None
        
        # Empty command
        is_valid, error = validate_network_operation_input("run_command", host="server.com", cmd="")
        assert not is_valid
        assert error is not None
        assert "Command cannot be empty" in error["error"]
        
        # Dangerous command
        is_valid, error = validate_network_operation_input("run_command", host="server.com", cmd="rm -rf / && echo done")
        assert not is_valid
        assert error is not None
        assert "dangerous characters" in error["error"]
    
    def test_port_scan_validation(self):
        """Test port scan validation."""
        # Valid scan
        is_valid, error = validate_network_operation_input("run_nmap_scan", target="192.168.1.1", top_ports=100)
        assert is_valid
        assert error is None
        
        # Too many ports
        is_valid, error = validate_network_operation_input("run_nmap_scan", target="192.168.1.1", top_ports=2000)
        assert not is_valid
        assert error is not None
        assert "Port count too high" in error["error"]


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_none_inputs(self):
        """Test None inputs across all validation functions."""
        validators = [
            (validate_ip_with_details, None),
            (validate_hostname, None),
            (validate_target, None),
            (validate_port, None)
        ]
        
        for validator_func, test_input in validators:
            is_valid, error, suggestion = validator_func(test_input)
            assert not is_valid
            assert error is not None
            assert suggestion is not None
    
    def test_empty_string_inputs(self):
        """Test empty string inputs."""
        empty_inputs = ["", "   ", "\t", "\n"]
        
        for empty_input in empty_inputs:
            # Test IP validation
            is_valid, error, suggestion = validate_ip_with_details(empty_input)
            assert not is_valid
            assert "cannot be empty" in error.lower()
            
            # Test hostname validation
            is_valid, error, suggestion = validate_hostname(empty_input)
            assert not is_valid
            assert "cannot be empty" in error.lower()
            
            # Test target validation
            is_valid, error, suggestion = validate_target(empty_input)
            assert not is_valid
            assert "cannot be empty" in error.lower()
    
    def test_very_long_inputs(self):
        """Test very long inputs."""
        long_string = "a" * 1000
        
        # Test hostname validation with very long input
        is_valid, error, suggestion = validate_hostname(long_string)
        assert not is_valid
        assert "too long" in error.lower()
    
    def test_unicode_inputs(self):
        """Test unicode and special character inputs."""
        unicode_inputs = [
            "тест.com",  # Cyrillic
            "测试.com",   # Chinese
            "🌐.com",    # Emoji
            "test.中国"   # IDN
        ]
        
        for unicode_input in unicode_inputs:
            # These should be handled gracefully
            is_valid, error, suggestion = validate_hostname(unicode_input)
            # We expect these to be invalid in our current implementation
            assert not is_valid
            assert error is not None
            assert suggestion is not None


if __name__ == "__main__":
    pytest.main([__file__])