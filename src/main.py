# src/main.py

"""
Main entry point for the Network CLI Assistant.

This script initializes the application, listens for user input,
and orchestrates the command processing flow.
"""

import json
import argparse
import sys
from src import core_functions
from src.dispatcher import parse_command
from src.utils import format_output
from src.logging_config import initialize_logging, get_logger

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network CLI Assistant")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="Enable debug logging")
    parser.add_argument("--no-log-file", action="store_true",
                       help="Disable logging to files")
    parser.add_argument("--log-dir", type=str,
                       help="Custom directory for log files")
    return parser.parse_args()

def main():
    """
    The main function that runs the CLI loop.
    """
    # Parse command line arguments
    args = parse_args()
    
    # Initialize logging system
    logger_kwargs = {
        "verbose": args.verbose,
        "debug": args.debug,
        "log_to_file": not args.no_log_file
    }
    if args.log_dir:
        from pathlib import Path
        logger_kwargs["log_dir"] = Path(args.log_dir)
    
    logger = initialize_logging(**logger_kwargs)
    
    # Clean up old logs on startup
    logger.cleanup_old_logs()
    
    print("Welcome to the Network CLI Assistant!")
    print("Type 'exit' or 'quit' to end the session.")
    
    if args.verbose:
        print("Verbose mode enabled - detailed operation information will be shown")
    if args.debug:
        print("Debug mode enabled - comprehensive logging is active")
    
    # Log application startup
    import logging
    app_logger = logging.getLogger("network_cli.app")
    app_logger.info("Network CLI Assistant started", extra={
        "verbose": args.verbose,
        "debug": args.debug,
        "log_to_file": not args.no_log_file
    })

    while True:
        try:
            user_input = input(">> ")

            if user_input.lower() in ["exit", "quit"]:
                app_logger.info("User requested application exit")
                print("Goodbye!")
                break

            if not user_input:
                continue

            # Log user input (without sensitive data)
            app_logger.debug(f"Processing user input: {user_input[:100]}{'...' if len(user_input) > 100 else ''}")

            # 2. Pass the input to the dispatcher to get a structured command.
            command = parse_command(user_input)
            
            # Log AI interaction
            logger.log_ai_interaction(user_input, command, "error" not in command)

            # Handle dispatcher errors
            if "error" in command:
                error_msg = command.get("message", "Could not understand command")
                app_logger.warning(f"Command parsing failed: {error_msg}")
                print(f"Error: {error_msg}")
                continue

            if not command or "function" not in command:
                app_logger.warning("Empty or invalid command received from dispatcher")
                print("Sorry, I could not understand that command. Please try again.")
                continue

            # 3. Execute the command using the appropriate core function.
            function_name = command.get("function")
            function_args = command.get("args", {})

            app_logger.info(f"Executing function: {function_name}", extra={
                "function": function_name,
                "function_args": function_args
            })

            try:
                func_to_call = getattr(core_functions, function_name)
                
                # Use operation context for logging
                with logger.operation_context(function_name, function_args.get('host') or function_args.get('target')):
                    result = func_to_call(**function_args)
                
                # Log the result (without sensitive data)
                success = result.get("success", True)
                if success:
                    app_logger.info(f"Function {function_name} completed successfully")
                else:
                    app_logger.error(f"Function {function_name} failed: {result.get('error', 'Unknown error')}")
                
                # 4. Print the result to the user in a readable format.
                print(format_output(result))

            except AttributeError:
                error_msg = f"The command '{function_name}' is not a valid function."
                app_logger.error(error_msg)
                print(f"Error: {error_msg}")
            except TypeError as e:
                error_msg = f"Error executing '{function_name}': {e}"
                app_logger.error(error_msg, exc_info=True)
                print(error_msg)
            except Exception as e:
                error_msg = f"Unexpected error executing '{function_name}': {e}"
                app_logger.error(error_msg, exc_info=True)
                print(f"Error: {error_msg}")

        except KeyboardInterrupt:
            app_logger.info("Application interrupted by user")
            print("\nGoodbye!")
            break
        except EOFError:
            app_logger.info("EOF received, exiting application")
            print("\nGoodbye!")
            break
        except Exception as e:
            app_logger.error(f"Unexpected error in main loop: {e}", exc_info=True)
            print(f"An unexpected error occurred: {e}")

    # Log application shutdown
    app_logger.info("Network CLI Assistant shutting down")

if __name__ == "__main__":
    main()
