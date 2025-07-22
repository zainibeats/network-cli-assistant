# tests/test_core_functions.py

"""
Tests for enhanced core network functions with educational context.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import subprocess
import socket

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.core_functions import (
    ping, traceroute, dns_lookup, run_nmap_scan, 
    _assess_port_security_risk, _get_port_security_recommendations
)

class TestPingEnhanced:
    """Test enhanced ping function with educational context."""
    
    @patch('subprocess.run')
    def test_ping_success_with_educational_context(self, mock_run):
        """Test successful ping with educational context included."""
        mock_run.return_value = MagicMock(
            stdout="""PING google.com (142.250.191.14): 56 data bytes
64 bytes from 142.250.191.14: icmp_seq=0 ttl=118 time=8.123 ms
64 bytes from 142.250.191.14: icmp_seq=1 ttl=118 time=7.456 ms
64 bytes from 142.250.191.14: icmp_seq=2 ttl=118 time=9.234 ms
64 bytes from 142.250.191.14: icmp_seq=3 ttl=118 time=8.567 ms

--- google.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
round-trip min/avg/max/stddev = 7.456/8.345/9.234/0.678 ms""",
            stderr="",
            returncode=0
        )
        
        result = ping("8.8.8.8")
        
        assert result["success"] == True
        assert "educational_context" in result
        assert "what_is_ping" in result["educational_context"]
        assert "ICMP" in result["educational_context"]["what_is_ping"]
        assert "rtt_meaning" in result["educational_context"]
        assert "Round-Trip Time" in result["educational_context"]["rtt_meaning"]
        assert "interpretation_guide" in result["educational_context"]
        assert "excellent_rtt" in result["educational_context"]["interpretation_guide"]
        assert "packet_loss_0" in result["educational_context"]["interpretation_guide"]
    
    @patch('subprocess.run')
    def test_ping_invalid_ip(self, mock_run):
        """Test ping with invalid IP address."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['ping'], stderr="ping: cannot resolve 999.999.999.999: Unknown host"
        )
        
        result = ping("999.999.999.999")
        
        assert result["success"] == False
        assert "cannot resolve" in result["error"]
        assert "educational_note" in result
        assert "host is down" in result["educational_note"]
    
    def test_ping_invalid_hostname(self):
        """Test ping with invalid hostname format."""
        result = ping("invalidhost")
        
        assert result["success"] == False
        assert "Invalid IP address or hostname" in result["error"]
        assert "educational_note" in result
    
    @patch('subprocess.run')
    def test_ping_failure_with_educational_note(self, mock_run):
        """Test ping failure includes educational context."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['ping'], stderr="ping: cannot resolve google.com: Unknown host"
        )
        
        result = ping("google.com")
        
        assert result["success"] == False
        assert "educational_note" in result
        assert "host is down" in result["educational_note"]
        assert "firewall blocking" in result["educational_note"]
        assert "DNS resolution" in result["educational_note"]

class TestTracerouteEnhanced:
    """Test enhanced traceroute function with educational context."""
    
    @patch('subprocess.run')
    def test_traceroute_success_with_educational_context(self, mock_run):
        """Test successful traceroute with comprehensive educational context."""
        mock_run.return_value = MagicMock(
            stdout="""traceroute to google.com (142.250.191.14), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.456 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms  5.789 ms
 3  142.250.191.14 (142.250.191.14)  8.901 ms  8.765 ms  8.987 ms""",
            stderr="",
            returncode=0
        )
        
        result = traceroute("8.8.8.8")
        
        assert result["success"] == True
        assert "educational_context" in result
        assert "what_is_traceroute" in result["educational_context"]
        assert "maps the path" in result["educational_context"]["what_is_traceroute"]
        assert "how_it_works" in result["educational_context"]
        assert "TTL" in result["educational_context"]["how_it_works"]
        assert "hop_explanation" in result["educational_context"]
        assert "timing_meaning" in result["educational_context"]
        assert "asterisk_meaning" in result["educational_context"]
        assert "interpretation_guide" in result["educational_context"]
        assert "troubleshooting_tips" in result["educational_context"]
        
        # Check interpretation guide content
        guide = result["educational_context"]["interpretation_guide"]
        assert "first_hops" in guide
        assert "middle_hops" in guide
        assert "final_hops" in guide
        assert "high_latency_hop" in guide
        
        # Check troubleshooting tips
        tips = result["educational_context"]["troubleshooting_tips"]
        assert isinstance(tips, list)
        assert len(tips) > 0
        assert any("Compare routes" in tip for tip in tips)
    
    def test_traceroute_invalid_host(self):
        """Test traceroute with invalid hostname."""
        result = traceroute("invalidhost")
        
        assert result["success"] == False
        assert "Invalid IP address or hostname" in result["error"]
        assert "educational_note" in result
    
    @patch('subprocess.run')
    def test_traceroute_failure_with_educational_note(self, mock_run):
        """Test traceroute failure includes educational context."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['traceroute'], stderr="traceroute: command not found"
        )
        
        result = traceroute("google.com")
        
        assert result["success"] == False
        assert "educational_note" in result
        assert "firewall blocking" in result["educational_note"]
        assert "routing issues" in result["educational_note"]

class TestDNSLookupEnhanced:
    """Test enhanced DNS lookup function with forward and reverse lookups."""
    
    @patch('socket.gethostbyname')
    @patch('socket.gethostbyaddr')
    def test_dns_forward_lookup_hostname(self, mock_gethostbyaddr, mock_gethostbyname):
        """Test DNS forward lookup starting with hostname."""
        mock_gethostbyname.return_value = "142.250.191.14"
        mock_gethostbyaddr.return_value = ("google.com", [], ["142.250.191.14"])
        
        result = dns_lookup("google.com")
        
        assert result["success"] == True
        assert "forward_lookup" in result
        assert "reverse_lookup" in result
        assert "educational_context" in result
        
        # Check forward lookup
        fl = result["forward_lookup"]
        assert fl["success"] == True
        assert fl["hostname"] == "google.com"
        assert fl["ip_address"] == "142.250.191.14"
        assert "explanation" in fl
        
        # Check reverse lookup
        rl = result["reverse_lookup"]
        assert rl["success"] == True
        assert rl["ip_address"] == "142.250.191.14"
        assert rl["hostname"] == "google.com"
        assert "consistency_check" in rl
        
        # Check educational context
        edu = result["educational_context"]
        assert "what_is_dns" in edu
        assert "translates human-readable" in edu["what_is_dns"]
        assert "forward_lookup_explanation" in edu
        assert "reverse_lookup_explanation" in edu
        assert "dns_record_types" in edu
        assert "troubleshooting_tips" in edu
        
        # Check DNS record types explanation
        record_types = edu["dns_record_types"]
        assert "A_record" in record_types
        assert "AAAA_record" in record_types
        assert "PTR_record" in record_types
        assert "CNAME_record" in record_types
        assert "MX_record" in record_types
    
    @patch('socket.gethostbyaddr')
    @patch('socket.gethostbyname')
    def test_dns_reverse_lookup_ip(self, mock_gethostbyname, mock_gethostbyaddr):
        """Test DNS reverse lookup starting with IP address."""
        mock_gethostbyaddr.return_value = ("google.com", [], ["8.8.8.8"])
        mock_gethostbyname.return_value = "8.8.8.8"
        
        result = dns_lookup("8.8.8.8")
        
        assert result["success"] == True
        assert "reverse_lookup" in result
        assert "forward_lookup" in result
        
        # Check reverse lookup (performed first for IP input)
        rl = result["reverse_lookup"]
        assert rl["success"] == True
        assert rl["ip_address"] == "8.8.8.8"
        assert rl["hostname"] == "google.com"
        
        # Check forward lookup (performed second)
        fl = result["forward_lookup"]
        assert fl["success"] == True
        assert fl["hostname"] == "google.com"
        assert fl["ip_address"] == "8.8.8.8"
        assert fl["consistency_check"] == True
    
    @patch('socket.gethostbyname')
    def test_dns_forward_lookup_failure(self, mock_gethostbyname):
        """Test DNS forward lookup failure."""
        mock_gethostbyname.side_effect = socket.gaierror("Name resolution failed")
        
        result = dns_lookup("nonexistent.domain")
        
        assert result["success"] == False
        assert "forward_lookup" in result
        assert result["forward_lookup"]["success"] == False
        assert "Could not resolve hostname" in result["forward_lookup"]["error"]
        assert "educational_context" in result  # The function includes educational_context even on failure
    
    @patch('socket.gethostbyaddr')
    def test_dns_reverse_lookup_failure(self, mock_gethostbyaddr):
        """Test DNS reverse lookup failure."""
        mock_gethostbyaddr.side_effect = socket.gaierror("Reverse lookup failed")
        
        result = dns_lookup("192.168.1.100")
        
        assert result["success"] == False
        assert "reverse_lookup" in result
        assert result["reverse_lookup"]["success"] == False
        assert "Could not perform reverse lookup" in result["reverse_lookup"]["error"]
    
    @patch('socket.gethostbyname')
    @patch('socket.gethostbyaddr')
    def test_dns_inconsistent_results(self, mock_gethostbyaddr, mock_gethostbyname):
        """Test DNS lookup with inconsistent forward/reverse results."""
        mock_gethostbyname.return_value = "142.250.191.14"
        mock_gethostbyaddr.return_value = ("different.domain.com", [], ["142.250.191.14"])
        
        result = dns_lookup("google.com")
        
        assert result["success"] == True
        fl = result["forward_lookup"]
        rl = result["reverse_lookup"]
        
        assert fl["hostname"] == "google.com"
        assert rl["hostname"] == "different.domain.com"
        assert rl["consistency_check"] == False
        assert "note" in rl

class TestNmapScanEnhanced:
    """Test enhanced nmap scan function with security analysis."""
    
    @patch('subprocess.run')
    def test_nmap_scan_success_with_security_analysis(self, mock_run):
        """Test successful nmap scan with comprehensive security analysis."""
        mock_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1"/>
        <hostnames>
            <hostname name="router.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.0"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="filtered"/>
                <service name="https"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
        
        mock_run.return_value = MagicMock(
            stdout=mock_xml,
            stderr="",
            returncode=0
        )
        
        result = run_nmap_scan("192.168.1.1", 10)
        
        assert result["success"] == True
        assert "host_info" in result
        assert "ports_found" in result
        assert "educational_context" in result
        assert "security_assessment" in result
        
        # Check host info
        host_info = result["host_info"]
        assert host_info["status"] == "up"
        assert host_info["ip"] == "192.168.1.1"
        assert host_info["hostname"] == "router.local"
        
        # Check ports found
        ports = result["ports_found"]
        assert len(ports) == 3
        
        # Check SSH port (22)
        ssh_port = next(p for p in ports if p["port"] == "22")
        assert ssh_port["state"] == "open"
        assert ssh_port["service"] == "ssh (OpenSSH 8.0)"
        assert ssh_port["security_risk"] == "medium"
        assert isinstance(ssh_port["recommendations"], list)
        
        # Check educational context
        edu = result["educational_context"]
        assert "what_is_nmap" in edu
        assert "port_states_explained" in edu
        assert "security_implications" in edu
        assert "common_ports_reference" in edu
        assert "best_practices" in edu
        
        # Check port states explanation
        states = edu["port_states_explained"]
        assert "open" in states
        assert "closed" in states
        assert "filtered" in states
        assert "potential entry point" in states["open"]
        
        # Check security implications
        security = edu["security_implications"]
        assert "attack surface" in security["open_ports"]
        assert "vulnerabilities" in security["service_versions"]
        
        # Check common ports reference
        ports_ref = edu["common_ports_reference"]
        assert "22" in ports_ref
        assert "SSH" in ports_ref["22"]
        assert "80" in ports_ref
        assert "443" in ports_ref
        
        # Check best practices
        practices = edu["best_practices"]
        assert isinstance(practices, list)
        assert any("necessary services" in practice for practice in practices)
        assert any("firewall" in practice for practice in practices)
    
    @patch('subprocess.run')
    def test_nmap_scan_no_ports_found(self, mock_run):
        """Test nmap scan when no ports are found."""
        mock_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1"/>
        <ports>
        </ports>
    </host>
</nmaprun>"""
        
        mock_run.return_value = MagicMock(
            stdout=mock_xml,
            stderr="",
            returncode=0
        )
        
        result = run_nmap_scan("192.168.1.1")
        
        assert result["success"] == True
        assert "No open or filtered ports found" in result["output"]
        assert "Good - No obvious entry points" in result["security_assessment"]
    
    @patch('subprocess.run')
    def test_nmap_scan_host_down(self, mock_run):
        """Test nmap scan when host appears down."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['nmap'], stderr="Host seems down. If it is really up, but blocking our ping probes"
        )
        
        result = run_nmap_scan("192.168.1.100")
        
        assert result["success"] == True
        assert "appears to be down" in result["output"]
        assert "educational_note" in result
        assert "-Pn flag" in result["educational_note"]
    
    @patch('subprocess.run')
    def test_nmap_scan_command_failure(self, mock_run):
        """Test nmap scan command failure."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['nmap'], stderr="nmap: command not found"
        )
        
        result = run_nmap_scan("192.168.1.1")
        
        assert result["success"] == False
        assert "educational_note" in result
        assert "nmap is installed" in result["educational_note"]

class TestSecurityAssessmentHelpers:
    """Test security assessment helper functions."""
    
    def test_assess_port_security_risk_high(self):
        """Test high-risk port assessment."""
        assert _assess_port_security_risk("23", "open", "telnet") == "high"
        assert _assess_port_security_risk("21", "open", "ftp") == "high"
        assert _assess_port_security_risk("3389", "open", "rdp") == "high"
        assert _assess_port_security_risk("1433", "open", "mssql") == "high"
    
    def test_assess_port_security_risk_medium(self):
        """Test medium-risk port assessment."""
        assert _assess_port_security_risk("22", "open", "ssh") == "medium"
        assert _assess_port_security_risk("25", "open", "smtp") == "medium"
        assert _assess_port_security_risk("53", "open", "dns") == "medium"
    
    def test_assess_port_security_risk_low(self):
        """Test low-risk port assessment."""
        assert _assess_port_security_risk("8080", "open", "http-alt") == "low"
        assert _assess_port_security_risk("22", "closed", "ssh") == "low"
        assert _assess_port_security_risk("22", "filtered", "ssh") == "low"
    
    def test_get_port_security_recommendations(self):
        """Test security recommendations for common ports."""
        ssh_recs = _get_port_security_recommendations("22", "ssh")
        assert isinstance(ssh_recs, list)
        assert any("key-based" in rec for rec in ssh_recs)
        assert any("root login" in rec for rec in ssh_recs)
        
        telnet_recs = _get_port_security_recommendations("23", "telnet")
        assert any("SSH" in rec for rec in telnet_recs)
        assert any("plain text" in rec for rec in telnet_recs)
        
        web_recs = _get_port_security_recommendations("80", "http")
        assert any("HTTPS" in rec for rec in web_recs)
        
        # Test unknown port
        unknown_recs = _get_port_security_recommendations("9999", "unknown")
        assert isinstance(unknown_recs, list)
        assert any("updated" in rec for rec in unknown_recs)

class TestEducationalContextIntegration:
    """Test that educational context is properly integrated across functions."""
    
    def test_all_functions_have_educational_docstrings(self):
        """Test that all enhanced functions have educational docstrings."""
        functions_to_test = [ping, traceroute, dns_lookup, run_nmap_scan]
        
        for func in functions_to_test:
            assert func.__doc__ is not None
            assert len(func.__doc__.strip()) > 100  # Substantial documentation
            # Check for educational content in docstring
            docstring = func.__doc__.lower()
            assert any(keyword in docstring for keyword in [
                'explain', 'educational', 'help', 'understand', 'concept', 'meaning'
            ])
    
    @patch('subprocess.run')
    def test_consistent_educational_structure(self, mock_run):
        """Test that educational context has consistent structure across functions."""
        # Mock successful ping
        mock_run.return_value = MagicMock(
            stdout="PING test output",
            stderr="",
            returncode=0
        )
        
        ping_result = ping("8.8.8.8")
        
        # Check educational context structure
        edu = ping_result["educational_context"]
        assert isinstance(edu, dict)
        assert "interpretation_guide" in edu
        assert isinstance(edu["interpretation_guide"], dict)
        
        # Mock successful traceroute
        mock_run.return_value = MagicMock(
            stdout="traceroute test output",
            stderr="",
            returncode=0
        )
        
        traceroute_result = traceroute("8.8.8.8")
        
        # Check educational context structure
        edu = traceroute_result["educational_context"]
        assert isinstance(edu, dict)
        assert "troubleshooting_tips" in edu
        assert isinstance(edu["troubleshooting_tips"], list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])