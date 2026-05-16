# src/main.py

"""
Main entry point for the Network CLI Assistant.

This script initializes the application, listens for user input,
and orchestrates the command processing flow.
"""

import argparse

from src.agent import handle_agent_message
from src.logging_config import initialize_logging


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network CLI Assistant")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-log-file", action="store_true", help="Disable logging to files")
    parser.add_argument("--log-dir", type=str, help="Custom directory for log files")
    return parser.parse_args()


def _confirm_command(command: str, reason: str | None = None) -> bool:
    """Ask the user before running a command that is not clearly read-only."""
    print()
    print("This command is not clearly read-only and needs approval.")
    if reason:
        print(f"Reason: {reason}")
    print(f"Command: {command}")
    answer = input("Run it? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


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
        "log_to_file": not args.no_log_file,
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
    app_logger.info(
        "Network CLI Assistant started",
        extra={"verbose": args.verbose, "debug": args.debug, "log_to_file": not args.no_log_file},
    )

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
            app_logger.debug(
                f"Processing user input: {user_input[:100]}{'...' if len(user_input) > 100 else ''}"
            )

            try:
                response = handle_agent_message(user_input, approval_callback=_confirm_command)
                logger.log_ai_interaction(user_input, {"status": "agent_handled"}, True)
                print(response)
            except Exception as e:
                error_msg = f"Unexpected error handling request: {e}"
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
