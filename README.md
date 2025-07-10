# Network CLI Assistant

Network CLI Assistant is a powerful command-line interface that leverages natural language processing to execute common network administration tasks. It allows you to perform network operations using simple, conversational commands, making network administration more accessible and efficient.

## 🌟 Features

- **Natural Language Processing**: Interact with your network using simple English commands
- **Common Network Operations**:
  - Port scanning with `nmap`
  - Network connection monitoring with `netstat`
  - Ping and traceroute diagnostics
  - DNS lookups
  - Custom command execution
- **Docker Support**: Consistent environment across all platforms
- **Extensible Architecture**: Easy to add new commands and functionality

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed on your system
- Google Gemini API key (for natural language processing)

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

   Edit the `.env` file and add your Google Gemini API key.

### Running with Docker (Recommended)

1. Build and start the container:

   ```bash
   docker compose up --build
   ```

2. To interact with the CLI, use:

   ```bash
   docker compose run --rm app
   ```

3. Run the application in the container:

   ```bash
   python -m src.main
   ```

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

## 💡 Usage Examples

Once the application is running, you can use natural language to perform network operations. Here are some examples:

- **Port Scanning**:

  ```text
  Scan ports on 192.168.1.1
  ```

- **Check Network Connections**:

  ```text
  Show me all listening ports
  ```

- **Network Diagnostics**:

  ```text
  Ping google.com
  ```

  ```text
  Trace route to example.com
  ```

- **DNS Lookup**:

  ```text
  What's the IP for google.com?
  ```

## 🛠️ Development

### Project Structure

```text
network-cli-assistant/
├── src/
│   ├── __init__.py
│   ├── main.py           # Main application entry point
│   ├── core_functions.py # Core network functions
│   ├── dispatcher.py     # Handles command dispatching
│   ├── utils.py          # Utility functions
│   └── config.py         # Configuration settings
├── docs/                 # AI Context
├── .env.example          # Example environment variables
├── .gitignore
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile            # Docker configuration
└── requirements.txt      # Python dependencies
```

### Adding New Commands

1. Add a new function in `core_functions.py`
2. Update the dispatcher in `dispatcher.py` to recognize the new command
3. Test your new functionality

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
