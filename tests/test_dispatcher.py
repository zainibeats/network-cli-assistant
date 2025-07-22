# tests/test_dispatcher.py

"""
Unit tests for the enhanced dispatcher module.

Tests various input patterns, networking terminology, error handling,
and fallback suggestions.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
from src.dispatcher import (
    parse_command, 
    normalize_input, 
    extract_network_entities, 
    generate_fallback_suggestions,
    validate_parsed_command
)


class TestDispatcher(unittest.TestCase):
    """Test cases for the enhanced dispatcher functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_ai_response = MagicMock()
        self.mock_model = MagicMock()
        self.mock_model.generate_content.return_value = self.mock_ai_response

    def test_normalize_input_basic(self):
        """Test basic input normalization."""
        # Test IP address normalization
        result = normalize_input("What's the IP address of google.com?")
        self.assertIn("ip", result)
        
        # Test DNS terminology
        result = normalize_input("Do a DNS lookup for example.com")
        self.assertIn("dns", result)
        
        # Test ping terminology
        result = normalize_input("Test connectivity to server")
        self.assertIn("ping", result)

    def test_normalize_input_synonyms(self):
        """Test normalization of networking synonyms."""
        # Test action synonyms
        result = normalize_input("Check the server status")
        self.assertIn("check", result)
        
        # Test target synonyms
        result = normalize_input("Ping the host machine")
        self.assertIn("server", result)

    def test_extract_network_entities_ip_addresses(self):
        """Test extraction of IP addresses from input."""
        test_cases = [
            ("ping 192.168.1.1", ["192.168.1.1"]),
            ("block 10.0.0.1 from 172.16.0.1", ["10.0.0.1", "172.16.0.1"]),
            ("scan 8.8.8.8 and 1.1.1.1", ["8.8.8.8", "1.1.1.1"]),
            ("no IPs here", [])
        ]
        
        for input_text, expected_ips in test_cases:
            with self.subTest(input_text=input_text):
                entities = extract_network_entities(input_text)
                self.assertEqual(entities['ip_addresses'], expected_ips)

    def test_extract_network_entities_domains(self):
        """Test extraction of domain names from input."""
        test_cases = [
            ("ping google.com", ["google.com"]),
            ("resolve example.org and test.net", ["example.org", "test.net"]),
            ("check github.io status", ["github.io"]),
            ("no domains here", [])
        ]
        
        for input_text, expected_domains in test_cases:
            with self.subTest(input_text=input_text):
                entities = extract_network_entities(input_text)
                # Note: regex might capture differently, so we check if expected domains are found
                for domain in expected_domains:
                    self.assertTrue(any(domain in found for found in entities['domains']))

    def test_extract_network_entities_ports(self):
        """Test extraction of port numbers from input."""
        test_cases = [
            ("scan port 80", ["80"]),
            ("check server:443", ["443"]),
            ("ports 22 and 3389", ["22", "3389"]),
            ("no ports mentioned", [])
        ]
        
        for input_text, expected_ports in test_cases:
            with self.subTest(input_text=input_text):
                entities = extract_network_entities(input_text)
                for port in expected_ports:
                    self.assertIn(port, entities['ports'])

    def test_generate_fallback_suggestions_ping(self):
        """Test fallback suggestions for ping-related inputs."""
        entities = {'ip_addresses': ['8.8.8.8'], 'domains': [], 'ports': []}
        suggestions = generate_fallback_suggestions("test connectivity", entities)
        
        self.assertTrue(any("ping" in suggestion for suggestion in suggestions))
        self.assertTrue(any("8.8.8.8" in suggestion for suggestion in suggestions))

    def test_generate_fallback_suggestions_dns(self):
        """Test fallback suggestions for DNS-related inputs."""
        entities = {'ip_addresses': [], 'domains': ['example.com'], 'ports': []}
        suggestions = generate_fallback_suggestions("resolve hostname", entities)
        
        self.assertTrue(any("dns_lookup" in suggestion for suggestion in suggestions))
        self.assertTrue(any("example.com" in suggestion for suggestion in suggestions))

    def test_generate_fallback_suggestions_scan(self):
        """Test fallback suggestions for port scan inputs."""
        entities = {'ip_addresses': ['192.168.1.1'], 'domains': [], 'ports': []}
        suggestions = generate_fallback_suggestions("port scan", entities)
        
        self.assertTrue(any("run_nmap_scan" in suggestion for suggestion in suggestions))
        self.assertTrue(any("192.168.1.1" in suggestion for suggestion in suggestions))

    def test_generate_fallback_suggestions_acl(self):
        """Test fallback suggestions for ACL-related inputs."""
        entities = {'ip_addresses': ['1.1.1.1', '2.2.2.2'], 'domains': [], 'ports': []}
        suggestions = generate_fallback_suggestions("block traffic", entities)
        
        self.assertTrue(any("generate_acl" in suggestion for suggestion in suggestions))
        self.assertTrue(any("deny" in suggestion for suggestion in suggestions))

    def test_generate_fallback_suggestions_netstat(self):
        """Test fallback suggestions for netstat inputs."""
        entities = {'ip_addresses': [], 'domains': [], 'ports': []}
        suggestions = generate_fallback_suggestions("listening ports", entities)
        
        self.assertTrue(any("run_netstat" in suggestion for suggestion in suggestions))

    def test_generate_fallback_suggestions_generic(self):
        """Test generic fallback suggestions when no patterns match."""
        entities = {'ip_addresses': [], 'domains': [], 'ports': []}
        suggestions = generate_fallback_suggestions("random text", entities)
        
        # Should return generic suggestions
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any("Try:" in suggestion for suggestion in suggestions))

    @patch('src.dispatcher.genai')
    def test_parse_command_successful(self, mock_genai):
        """Test successful command parsing."""
        # Mock the AI response
        mock_response = MagicMock()
        mock_response.text = '{"function": "ping", "args": {"host": "google.com"}}'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("ping google")
        
        self.assertEqual(result["function"], "ping")
        self.assertEqual(result["args"]["host"], "google.com")

    @patch('src.dispatcher.genai')
    def test_parse_command_json_with_code_blocks(self, mock_genai):
        """Test parsing AI response with markdown code blocks."""
        # Mock the AI response with code blocks
        mock_response = MagicMock()
        mock_response.text = '```json\n{"function": "dns_lookup", "args": {"host": "example.com"}}\n```'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("resolve example.com")
        
        self.assertEqual(result["function"], "dns_lookup")
        self.assertEqual(result["args"]["host"], "example.com")

    @patch('src.dispatcher.genai')
    def test_parse_command_ambiguous_response(self, mock_genai):
        """Test handling of ambiguous AI responses."""
        # Mock ambiguous AI response
        mock_response = MagicMock()
        mock_response.text = '{"error": "ambiguous", "suggestions": ["ping host", "dns_lookup host"]}'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("check host")
        
        self.assertEqual(result["error"], "ambiguous")
        self.assertIn("suggestions", result)
        self.assertTrue(len(result["suggestions"]) > 0)

    @patch('src.dispatcher.genai')
    def test_parse_command_json_parse_error(self, mock_genai):
        """Test handling of JSON parse errors."""
        # Mock invalid JSON response
        mock_response = MagicMock()
        mock_response.text = 'invalid json response'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("some command")
        
        self.assertEqual(result["error"], "parse_error")
        self.assertIn("suggestions", result)

    @patch('src.dispatcher.genai')
    def test_parse_command_ai_error(self, mock_genai):
        """Test handling of AI processing errors."""
        # Mock AI exception
        mock_genai.GenerativeModel.side_effect = Exception("AI service unavailable")
        
        result = parse_command("ping google")
        
        self.assertEqual(result["error"], "ai_error")
        self.assertIn("AI processing failed", result["message"])
        self.assertIn("suggestions", result)

    def test_parse_command_empty_input(self):
        """Test handling of empty input."""
        test_cases = ["", "   ", None]
        
        for empty_input in test_cases:
            with self.subTest(input=empty_input):
                result = parse_command(empty_input)
                self.assertEqual(result["error"], "empty_input")
                self.assertIn("suggestions", result)

    @patch('src.dispatcher.genai')
    def test_parse_command_missing_function_field(self, mock_genai):
        """Test handling of AI response missing function field."""
        # Mock response without function field
        mock_response = MagicMock()
        mock_response.text = '{"args": {"host": "example.com"}}'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("some command")
        
        self.assertEqual(result["error"], "ai_error")
        self.assertIn("Response missing 'function' field", result["message"])

    @patch('src.dispatcher.genai')
    def test_parse_command_unknown_function(self, mock_genai):
        """Test handling of unknown function in AI response."""
        # Mock response with unknown function
        mock_response = MagicMock()
        mock_response.text = '{"function": "unknown_function", "args": {}}'
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = parse_command("some command")
        
        self.assertEqual(result["error"], "ai_error")
        self.assertIn("Unknown function", result["message"])

    def test_validate_parsed_command_valid(self):
        """Test validation of valid parsed commands."""
        valid_commands = [
            {"function": "ping", "args": {"host": "google.com"}},
            {"function": "dns_lookup", "args": {"host": "example.com"}},
            {"function": "run_nmap_scan", "args": {"target": "192.168.1.1", "top_ports": 10}},
            {"error": "ambiguous", "suggestions": ["ping host"]}  # Error responses are valid
        ]
        
        for command in valid_commands:
            with self.subTest(command=command):
                is_valid, error_msg = validate_parsed_command(command)
                self.assertTrue(is_valid)
                self.assertIsNone(error_msg)

    def test_validate_parsed_command_invalid(self):
        """Test validation of invalid parsed commands."""
        invalid_commands = [
            {},  # Missing function field
            {"function": "nonexistent_function", "args": {}},  # Unknown function
            {"function": "ping", "args": {}},  # Missing required parameter
        ]
        
        for command in invalid_commands:
            with self.subTest(command=command):
                is_valid, error_msg = validate_parsed_command(command)
                self.assertFalse(is_valid)
                self.assertIsNotNone(error_msg)


class TestDispatcherIntegration(unittest.TestCase):
    """Integration tests for dispatcher with various input patterns."""

    def setUp(self):
        """Set up integration test fixtures."""
        # Common test inputs that should be handled
        self.test_inputs = [
            # Ping variations
            ("ping google", "ping"),
            ("test connectivity to 8.8.8.8", "ping"),
            ("check if github.com is up", "ping"),
            ("icmp test to server", "ping"),
            
            # DNS lookup variations
            ("what's the ip of google.com", "dns_lookup"),
            ("resolve example.org", "dns_lookup"),
            ("nslookup github.com", "dns_lookup"),
            ("find ip address for site.com", "dns_lookup"),
            
            # Port scan variations
            ("scan ports on 192.168.1.1", "run_nmap_scan"),
            ("nmap scan of server", "run_nmap_scan"),
            ("check open ports on host", "run_nmap_scan"),
            ("port discovery on target", "run_nmap_scan"),
            
            # Traceroute variations
            ("trace route to google.com", "traceroute"),
            ("tracert to 8.8.8.8", "traceroute"),
            ("show path to destination", "traceroute"),
            
            # ACL variations
            ("block 1.1.1.1 from 2.2.2.2", "generate_acl"),
            ("deny traffic from source to dest", "generate_acl"),
            ("create firewall rule", "generate_acl"),
            
            # Netstat variations
            ("show listening ports", "run_netstat"),
            ("netstat command", "run_netstat"),
            ("list open connections", "run_netstat"),
        ]

    @patch('src.dispatcher.genai')
    def test_various_input_patterns(self, mock_genai):
        """Test that various input patterns are handled appropriately."""
        for input_text, expected_function in self.test_inputs:
            with self.subTest(input=input_text, expected=expected_function):
                # Mock appropriate AI response
                mock_response = MagicMock()
                mock_response.text = f'{{"function": "{expected_function}", "args": {{"host": "example.com"}}}}'
                mock_model = MagicMock()
                mock_model.generate_content.return_value = mock_response
                mock_genai.GenerativeModel.return_value = mock_model
                
                result = parse_command(input_text)
                
                # Should not be an error response
                self.assertNotIn("error", result)
                # Should have the expected function
                self.assertEqual(result.get("function"), expected_function)

    def test_networking_terminology_coverage(self):
        """Test that networking terminology mappings are comprehensive."""
        from src.dispatcher import NETWORK_TERMINOLOGY
        
        # Ensure we have mappings for key networking concepts
        required_terms = ['ip', 'dns', 'ping', 'trace', 'scan', 'acl', 'ssh', 'netstat']
        
        for term in required_terms:
            with self.subTest(term=term):
                self.assertIn(term, NETWORK_TERMINOLOGY)
                self.assertTrue(len(NETWORK_TERMINOLOGY[term]) > 0)

    def test_pattern_extraction_coverage(self):
        """Test that network pattern extraction covers common cases."""
        from src.dispatcher import NETWORKING_PATTERNS
        
        # Test that we can extract common network entities
        test_text = "ping 192.168.1.1 and resolve google.com on port 80"
        entities = extract_network_entities(test_text)
        
        self.assertTrue(len(entities['ip_addresses']) > 0)
        self.assertTrue(len(entities['domains']) > 0)
        self.assertTrue(len(entities['ports']) > 0)


if __name__ == '__main__':
    unittest.main()