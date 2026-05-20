# src/main.py

"""
Main entry point for the CLI Assistant.

This script initializes the application, listens for user input,
and orchestrates the command processing flow.
"""

import argparse

from src.agent import handle_agent_message
from src.formatting.colors import Colors
from src.knowledgebase import ensure_knowledgebase
from src.logging_config import initialize_logging
from src.policy import load_policy
from src.terminal_io import discard_pending_input, read_prompt

SESSION_APPROVED_COMMANDS: set[str] = set()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="CLI Assistant")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-log-file", action="store_true", help="Disable logging to files")
    parser.add_argument("--log-dir", type=str, help="Custom directory for log files")
    return parser.parse_args()


def _confirm_command(command: str, reason: str | None = None) -> bool:
    """Ask the user before running a command that is not clearly read-only."""
    if command in SESSION_APPROVED_COMMANDS:
        return True

    discard_pending_input()
    policy = load_policy()
    allow_session = bool(policy.get("approval", {}).get("allow_session_approval", True))
    print()
    print(f"{Colors.YELLOW}{Colors.BOLD}Approval required{Colors.END}")
    if reason:
        print(f"{Colors.YELLOW}Reason:{Colors.END} {reason}")
    print(f"{Colors.CYAN}Command:{Colors.END} {command}")
    if allow_session:
        prompt = "Run it? [y]es / [n]o / approve for [s]ession: "
    else:
        prompt = "Run it? [y/N] "
    answer = read_prompt(prompt).strip().lower()
    if allow_session and answer in {"s", "session"}:
        SESSION_APPROVED_COMMANDS.add(command)
        return True
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
    context_root = ensure_knowledgebase()
    load_policy()

    # Clean up old logs on startup
    logger.cleanup_old_logs()

    print(f"{Colors.BOLD}CLI Assistant{Colors.END}")
    print(f"Runtime context: {context_root}")
    print("Type 'exit' or 'quit' to end the session.")

    if args.verbose:
        print("Verbose mode enabled - detailed operation information will be shown")
    if args.debug:
        print("Debug mode enabled - comprehensive logging is active")

    # Log application startup
    import logging

    app_logger = logging.getLogger("cli_assistant.app")
    app_logger.info(
        "CLI Assistant started",
        extra={"verbose": args.verbose, "debug": args.debug, "log_to_file": not args.no_log_file},
    )

    while True:
        try:
            user_input = read_prompt(">> ")

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
                if args.verbose:
                    print(f"{Colors.BLUE}agent: planning and running approved local steps...{Colors.END}")
                response = handle_agent_message(user_input, approval_callback=_confirm_command)
                logger.log_ai_interaction(user_input, {"status": "agent_handled"}, True)
                print(f"{Colors.GREEN}assistant>{Colors.END}")
                print(response)
                discard_pending_input()
            except Exception as e:
                error_msg = f"Unexpected error handling request: {e}"
                app_logger.error(error_msg, exc_info=True)
                print(f"Error: {error_msg}")
                discard_pending_input()

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
    app_logger.info("CLI Assistant shutting down")


if __name__ == "__main__":
    main()
