# Network CLI Assistant

> **Note**: This project contains AI-generated code.

Network CLI Assistant is a powerful command-line interface that leverages natural language processing to execute common network administration tasks. It allows you to perform network operations using simple, conversational commands, making network administration more accessible and efficient. 

## Features

- **Natural Language Processing**: Interact with your network using simple English commands powered by Google Gemini API
- **Comprehensive Network Operations**:
  - Advanced port scanning with `nmap` (configurable port ranges, specific ports, network discovery)
  - Network connection monitoring with `netstat`
  - Ping and traceroute diagnostics with detailed analysis
  - Forward and reverse DNS lookups
  - Host discovery and network scanning
- **Enhanced Output**: Clear, educational formatting with security risk assessments and recommendations
- **Robust Error Handling**: Comprehensive validation and helpful error messages
- **Docker Support**: Consistent environment across all platforms
- **Modular Architecture**: Clean, maintainable codebase with separated concerns

## Quick Start

### Prerequisites

- Docker and Docker Compose installed on your system
- A local OpenAI-compatible model endpoint, such as LM Studio or Ollama

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/zainibeats/network-cli-assistant
   cd network-cli-assistant
   ```

2. Copy the example environment file and add your API key:

   ```bash
   cp .env.example .env
   ```

   Edit the `.env` file and set your local model name and endpoint.

### Running with Docker (Recommended)

1. Build the container:

   ```bash
   docker compose build
   ```

2. To run the container and interact with the CLI, use:

   ```bash
   docker compose run --rm network-cli-assistant
   ```

By default the compose file expects an OpenAI-compatible endpoint at
`http://127.0.0.1:1234/v1`, which matches common LM Studio defaults when using
host networking. Ollama users can set `OPENAI_COMPATIBLE_BASE_URL` in `.env`.

### Running Locally

1. Install Python 3.8+ if not already installed

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:

   ```bash
   python -m src.main
   ```

## Usage Examples

Once the application is running, you can use natural language to perform network operations. The AI assistant will interpret your intent and execute the appropriate network functions.

### Basic Network Diagnostics

- **Ping Testing**:
  ```text
  Ping google.com
  Test connectivity to 192.168.1.1
  Check if server.example.com is reachable
  ```

- **Traceroute Analysis**:
  ```text
  Trace route to google
  Show me the path to 8.8.8.8
  Traceroute to my server
  ```

- **DNS Lookups**:
  ```text
  What's the IP for google?
  Reverse lookup 8.8.8.8
  DNS lookup for example.com
  ```

### Port Scanning and Discovery

- **Basic Port Scanning**:
  ```text
  Scan ports on 192.168.1.1
  Check open ports on server.example.com
  Nmap scan of 10.0.0.1
  ```

- **Advanced Port Scanning**:
  ```text
  Scan top 100 ports on 192.168.1.1
  Check ports 80,443,22 on example.com
  Scan port range 1-1000 on 10.0.0.1
  ```

- **Network Discovery**:
  ```text
  Discover hosts on 192.168.1.0/24
  Find active hosts in my network
  Scan network 10.0.0.0/24 for hosts
  ```

### System Monitoring

- **Local Port Monitoring**:
  ```text
  Show me all listening ports
  What ports are open locally?
  List all network connections
  ```

## Development

### Project Structure

```text
network-cli-assistant/
├── src/
│   ├── __init__.py
│   ├── main.py              # Main application entry point
│   ├── core_functions.py    # Compatibility layer for network functions
│   ├── dispatcher.py        # AI-powered command dispatching
│   ├── config.py           # Configuration settings
│   ├── logging_config.py   # Logging configuration
│   ├── utils.py            # General utility functions
│   ├── network/            # Network operations modules
│   │   ├── __init__.py
│   │   ├── connectivity.py # Ping and traceroute
│   │   ├── dns.py          # DNS lookup functions
│   │   ├── discovery.py    # Host discovery
│   │   ├── scanning.py     # Port scanning with nmap/netstat
│   │   └── analysis.py     # Result analysis and interpretation
│   ├── validation/         # Input validation modules
│   │   ├── __init__.py
│   │   ├── network.py      # Network-specific validation
│   │   └── input.py        # General input validation
│   ├── formatting/         # Output formatting modules
│   │   ├── __init__.py
│   │   ├── output.py       # Output formatting and display
│   │   └── colors.py       # Color constants and terminal formatting
│   └── error_handling/     # Error handling modules
│       ├── __init__.py
│       ├── network.py      # Network error handling
│       └── common.py       # Common error handling utilities
├── tests/                  # Unit and integration tests
├── docs/                   # Documentation and AI context
├── .kiro/                  # Kiro IDE configuration and specs
├── .env.example            # Example environment variables
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker configuration
└── requirements.txt        # Python dependencies
```

## Understanding Output and Results

### Port Scan Results

The tool provides detailed analysis of port scan results including:

- **Security Risk Assessment**: Each open port is categorized as Critical, High, Medium, or Low risk
- **Service Identification**: Automatic detection of running services and versions
- **Security Recommendations**: Specific advice for securing each discovered service
- **Network Summary**: For network scans, organized results by host with risk indicators

Example output interpretation:
```text
Host 192.168.1.100:
  • Port 22 (ssh OpenSSH 8.0) - MEDIUM RISK
    Recommendations: Use key-based authentication, disable root login, change default port
  • Port 3389 (ms-wbt-server) - HIGH RISK  
    Recommendations: Use Network Level Authentication, restrict access by IP, use strong passwords
```

### DNS Lookup Results

DNS lookups provide both forward and reverse resolution:
- **Forward Lookup**: Hostname to IP address resolution
- **Reverse Lookup**: IP address to hostname resolution  
- **Consistency Checking**: Verification that forward and reverse lookups match
- **Error Analysis**: Clear explanations when DNS resolution fails

### Network Diagnostics

Ping and traceroute results include:
- **Response Time Analysis**: RTT measurements and packet loss statistics
- **Network Path Visualization**: Hop-by-hop routing information
- **Connectivity Assessment**: Clear indicators of network reachability
- **Error Categorization**: Specific error types (DNS failure, network unreachable, timeout)

## Security Features

### Input Validation

- **IP Address Validation**: Comprehensive validation of IPv4 addresses and CIDR notation
- **Hostname Validation**: DNS-compliant hostname checking with helpful error messages
- **Command Sanitization**: Protection against command injection attacks
- **Parameter Validation**: Type checking and range validation for all function parameters

### Secure Operations

- **Credential Management**: Environment variable-based configuration without hardcoded secrets
- **Network Isolation**: Configurable timeouts and connection limits
- **Audit Logging**: Comprehensive logging of all network operations for security monitoring

### Risk Assessment

- **Port Security Analysis**: Automatic categorization of security risks for discovered services
- **Vulnerability Identification**: Recognition of commonly exploited services and configurations
- **Remediation Guidance**: Specific recommendations for securing network services
- **Compliance Support**: Output suitable for security audits and compliance reporting

### Adding New Commands

The modular architecture makes it easy to extend functionality:

1. **Add Network Function**: Create new function in appropriate `src/network/` module
2. **Follow Interface Pattern**: Use standard return format with success/error handling
3. **Add Validation**: Include input validation using `src/validation/` modules
4. **Update Documentation**: Function docstrings automatically become part of AI context
5. **Write Tests**: Add unit tests following existing patterns

## Troubleshooting

### Common Issues

**"Command not found" errors**:
- Ensure `nmap`, `ping`, `traceroute`, and `netstat` are installed on your system
- For Docker users, these tools are included in the container

**"Permission denied" errors**:
- Some network operations require elevated privileges
- Run with `sudo` if needed, or use Docker which handles permissions

**"DNS resolution failed" errors**:
- Check your network connection and DNS configuration
- Verify the hostname is correct and accessible
- Try using IP addresses directly for testing

**"Connection timeout" errors**:
- Target host may be down or blocking connections
- Firewall rules may be preventing access
- Increase timeout values in configuration if needed

**AI parsing errors**:
- Ensure your Gemini API key is correctly configured
- Check your internet connection for API access
- Try rephrasing your command more clearly

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
