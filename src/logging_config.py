# src/logging_config.py

"""
Logging and debugging configuration for the Network CLI Assistant.

This module provides comprehensive logging capabilities including:
- Structured logging for network operations
- Verbose mode for detailed operation information
- Debug output to help users understand tool behavior
- Log rotation and cleanup for long-running sessions
"""

import logging
import logging.handlers
import os
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Union
from contextlib import contextmanager

# Default log directory
DEFAULT_LOG_DIR = Path.home() / ".network_cli_assistant" / "logs"

class NetworkOperationFilter(logging.Filter):
    """Filter to add network operation context to log records."""
    
    def __init__(self):
        super().__init__()
        self.current_operation = None
        self.current_target = None
        self.operation_id = None
    
    def set_operation_context(self, operation: str, target: str = None, operation_id: str = None):
        """Set the current operation context for logging."""
        self.current_operation = operation
        self.current_target = target
        self.operation_id = operation_id
    
    def clear_operation_context(self):
        """Clear the current operation context."""
        self.current_operation = None
        self.current_target = None
        self.operation_id = None
    
    def filter(self, record):
        """Add operation context to log records."""
        record.operation = self.current_operation or "unknown"
        record.target = self.current_target or "unknown"
        record.operation_id = self.operation_id or "unknown"
        return True

class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "operation": getattr(record, 'operation', 'unknown'),
            "target": getattr(record, 'target', 'unknown'),
            "operation_id": getattr(record, 'operation_id', 'unknown')
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 
                          'exc_text', 'stack_info', 'operation', 'target', 'operation_id']:
                log_entry[key] = value
        
        return json.dumps(log_entry)

class VerboseFormatter(logging.Formatter):
    """Human-readable formatter for verbose output."""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s [%(levelname)s] %(operation)s:%(target)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

class NetworkLogger:
    """Main logging class for the Network CLI Assistant."""
    
    def __init__(self, 
                 log_dir: Optional[Path] = None,
                 verbose: bool = False,
                 debug: bool = False,
                 log_to_file: bool = True,
                 max_log_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5,
                 cleanup_days: int = 30):
        """
        Initialize the network logger.
        
        Args:
            log_dir: Directory for log files (default: ~/.network_cli_assistant/logs)
            verbose: Enable verbose console output
            debug: Enable debug level logging
            log_to_file: Whether to log to files
            max_log_size: Maximum size of each log file in bytes
            backup_count: Number of backup log files to keep
            cleanup_days: Number of days to keep old log files
        """
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.verbose = verbose
        self.debug = debug
        self.log_to_file = log_to_file
        self.max_log_size = max_log_size
        self.backup_count = backup_count
        self.cleanup_days = cleanup_days
        
        # Create log directory
        if self.log_to_file:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize loggers
        self._setup_loggers()
        
        # Operation filter for context
        self.operation_filter = NetworkOperationFilter()
        
        # Add filter to all handlers
        for handler in logging.getLogger().handlers:
            handler.addFilter(self.operation_filter)
    
    def _setup_loggers(self):
        """Set up the logging configuration."""
        # Clear any existing handlers
        logging.getLogger().handlers.clear()
        
        # Set root logger level
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if self.verbose:
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(VerboseFormatter())
        else:
            console_handler.setLevel(logging.WARNING)
            console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        
        root_logger.addHandler(console_handler)
        
        if self.log_to_file:
            # Main log file (rotating)
            main_log_file = self.log_dir / "network_cli.log"
            main_handler = logging.handlers.RotatingFileHandler(
                main_log_file,
                maxBytes=self.max_log_size,
                backupCount=self.backup_count
            )
            main_handler.setLevel(logging.DEBUG if self.debug else logging.INFO)
            main_handler.setFormatter(VerboseFormatter())
            root_logger.addHandler(main_handler)
            
            # JSON log file for structured logging
            json_log_file = self.log_dir / "network_cli.json"
            json_handler = logging.handlers.RotatingFileHandler(
                json_log_file,
                maxBytes=self.max_log_size,
                backupCount=self.backup_count
            )
            json_handler.setLevel(logging.DEBUG if self.debug else logging.INFO)
            json_handler.setFormatter(JsonFormatter())
            root_logger.addHandler(json_handler)
            
            # Error log file
            error_log_file = self.log_dir / "errors.log"
            error_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=self.max_log_size,
                backupCount=self.backup_count
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(VerboseFormatter())
            root_logger.addHandler(error_handler)
    
    @contextmanager
    def operation_context(self, operation: str, target: str = None):
        """
        Context manager for logging network operations.
        
        Args:
            operation: Name of the network operation
            target: Target host/IP for the operation
        """
        operation_id = f"{operation}_{int(time.time() * 1000)}"
        
        # Set operation context
        self.operation_filter.set_operation_context(operation, target, operation_id)
        
        logger = logging.getLogger(f"network_cli.{operation}")
        
        try:
            logger.info(f"Starting {operation} operation", extra={
                "operation_start": True,
                "target": target,
                "operation_id": operation_id
            })
            
            start_time = time.time()
            yield logger
            
            duration = time.time() - start_time
            logger.info(f"Completed {operation} operation in {duration:.2f}s", extra={
                "operation_end": True,
                "duration": duration,
                "target": target,
                "operation_id": operation_id
            })
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Failed {operation} operation after {duration:.2f}s: {e}", extra={
                "operation_error": True,
                "duration": duration,
                "target": target,
                "operation_id": operation_id,
                "error": str(e)
            }, exc_info=True)
            raise
        
        finally:
            # Clear operation context
            self.operation_filter.clear_operation_context()
    
    def log_command_execution(self, command: str, host: str, result: Dict[str, Any]):
        """
        Log command execution details.
        
        Args:
            command: The command that was executed
            host: The target host
            result: The execution result
        """
        logger = logging.getLogger("network_cli.command")
        
        success = result.get("success", False)
        exit_code = result.get("exit_code", -1)
        
        if success:
            logger.info(f"Command executed successfully on {host}", extra={
                "command": command,
                "host": host,
                "exit_code": exit_code,
                "stdout_length": len(result.get("stdout", "")),
                "stderr_length": len(result.get("stderr", ""))
            })
        else:
            logger.error(f"Command failed on {host}", extra={
                "command": command,
                "host": host,
                "exit_code": exit_code,
                "error": result.get("error", "Unknown error"),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", "")
            })
    
    def log_network_scan(self, target: str, scan_type: str, result: Dict[str, Any]):
        """
        Log network scan details.
        
        Args:
            target: The scan target
            scan_type: Type of scan (nmap, ping, etc.)
            result: The scan result
        """
        logger = logging.getLogger("network_cli.scan")
        
        success = result.get("success", False)
        
        if success:
            ports_found = result.get("ports_found", [])
            open_ports = [p for p in ports_found if p.get("state") == "open"]
            
            logger.info(f"{scan_type} scan completed for {target}", extra={
                "target": target,
                "scan_type": scan_type,
                "total_ports_scanned": len(ports_found),
                "open_ports_found": len(open_ports),
                "open_ports": [p.get("port") for p in open_ports]
            })
        else:
            logger.error(f"{scan_type} scan failed for {target}", extra={
                "target": target,
                "scan_type": scan_type,
                "error": result.get("error", "Unknown error")
            })
    
    def log_validation_error(self, field: str, value: str, error: str):
        """
        Log input validation errors.
        
        Args:
            field: The field that failed validation
            value: The invalid value
            error: The validation error message
        """
        logger = logging.getLogger("network_cli.validation")
        logger.warning(f"Validation failed for {field}", extra={
            "field": field,
            "invalid_value": value,
            "validation_error": error
        })
    
    def log_ai_interaction(self, user_input: str, parsed_command: Dict[str, Any], success: bool):
        """
        Log AI dispatcher interactions.
        
        Args:
            user_input: The original user input
            parsed_command: The parsed command from AI
            success: Whether parsing was successful
        """
        logger = logging.getLogger("network_cli.ai")
        
        if success:
            logger.info("AI successfully parsed user command", extra={
                "user_input": user_input,
                "parsed_function": parsed_command.get("function"),
                "function_args": parsed_command.get("args", {}),
                "input_length": len(user_input)
            })
        else:
            logger.warning("AI failed to parse user command", extra={
                "user_input": user_input,
                "error": parsed_command.get("error", "Unknown error"),
                "input_length": len(user_input)
            })
    
    def cleanup_old_logs(self):
        """Clean up old log files based on cleanup_days setting."""
        if not self.log_to_file:
            return
        
        logger = logging.getLogger("network_cli.cleanup")
        cutoff_date = datetime.now() - timedelta(days=self.cleanup_days)
        
        cleaned_files = 0
        for log_file in self.log_dir.glob("*.log*"):
            try:
                file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_mtime < cutoff_date:
                    log_file.unlink()
                    cleaned_files += 1
                    logger.debug(f"Cleaned up old log file: {log_file}")
            except Exception as e:
                logger.error(f"Failed to clean up log file {log_file}: {e}")
        
        if cleaned_files > 0:
            logger.info(f"Cleaned up {cleaned_files} old log files")
    
    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get statistics about log files.
        
        Returns:
            Dictionary with log file statistics
        """
        if not self.log_to_file:
            return {"log_to_file": False}
        
        stats = {
            "log_to_file": True,
            "log_directory": str(self.log_dir),
            "log_files": []
        }
        
        total_size = 0
        for log_file in self.log_dir.glob("*.log*"):
            try:
                file_stat = log_file.stat()
                file_info = {
                    "name": log_file.name,
                    "size": file_stat.st_size,
                    "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                }
                stats["log_files"].append(file_info)
                total_size += file_stat.st_size
            except Exception:
                pass
        
        stats["total_log_size"] = total_size
        stats["log_file_count"] = len(stats["log_files"])
        
        return stats

# Global logger instance
_logger_instance: Optional[NetworkLogger] = None

def get_logger() -> NetworkLogger:
    """Get the global logger instance."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = NetworkLogger()
    return _logger_instance

def initialize_logging(verbose: bool = False, debug: bool = False, **kwargs) -> NetworkLogger:
    """
    Initialize the global logging system.
    
    Args:
        verbose: Enable verbose console output
        debug: Enable debug level logging
        **kwargs: Additional arguments for NetworkLogger
    
    Returns:
        The initialized NetworkLogger instance
    """
    global _logger_instance
    _logger_instance = NetworkLogger(verbose=verbose, debug=debug, **kwargs)
    return _logger_instance

def log_operation(operation: str, target: str = None):
    """
    Decorator for logging network operations.
    
    Args:
        operation: Name of the operation
        target: Target host/IP (can be extracted from function args if None)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger()
            
            # Try to extract target from function arguments if not provided
            actual_target = target
            if actual_target is None:
                # Common parameter names for targets
                for param_name in ['host', 'target', 'hostname']:
                    if param_name in kwargs:
                        actual_target = kwargs[param_name]
                        break
                    # Check positional args for functions with known signatures
                    if len(args) > 0 and param_name == 'host':
                        actual_target = args[0]
                        break
            
            with logger.operation_context(operation, actual_target):
                return func(*args, **kwargs)
        
        return wrapper
    return decorator