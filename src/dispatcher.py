# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

import inspect
import json
import logging
from typing import Optional, Tuple

from .command_catalog import get_function, has_function
from .command_result import parser_error
from .deterministic_parser import parse_deterministic
from .llm_providers import parse_with_provider, selected_provider
from .prompt_builder import build_command_parser_prompt

try:
    from dotenv import load_dotenv
except ImportError:

    def load_dotenv():
        return False


load_dotenv()


def get_enhanced_prompt():
    """
    Generate a prompt for AI command parsing.
    """
    return build_command_parser_prompt()


def parse_command(user_input: str) -> dict:
    """
    Enhanced command parser with better networking terminology understanding.

    Args:
        user_input: The raw string from the user.

    Returns:
        A dictionary representing the function to call and its arguments.
        Returns error dict with suggestions if parsing fails.
    """
    logger = logging.getLogger("network_cli.dispatcher")

    if not user_input or not user_input.strip():
        logger.warning("Empty input received")
        return parser_error("empty_input", "Please provide a command")

    deterministic_result = parse_deterministic(user_input)
    if deterministic_result:
        logger.info(
            "Command parsed deterministically",
            extra={"status": deterministic_result.get("status")},
        )
        return deterministic_result

    try:
        prompt = get_enhanced_prompt()
        full_prompt = prompt + user_input

        logger.debug(
            "Sending request to LLM for command parsing",
            extra={
                "provider": selected_provider(),
                "input_length": len(user_input),
                "prompt_length": len(full_prompt),
            },
        )

        parsed_response = parse_with_provider(full_prompt)

        logger.debug(
            "AI response parsed successfully",
            extra={
                "function": parsed_response.get("function"),
                "args_count": len(parsed_response.get("args", {})),
            },
        )

        # Validate the response structure
        if "error" in parsed_response:
            if parsed_response["error"] == "ambiguous":
                logger.warning("AI reported ambiguous command")
                return parser_error("ambiguous", "Command is ambiguous")

        # Validate that we have a function and args
        if "function" not in parsed_response:
            logger.error("AI response missing 'function' field")
            raise ValueError("Response missing 'function' field")

        if "args" not in parsed_response:
            parsed_response["args"] = {}
        parsed_response.setdefault("status", "ready")
        parsed_response.setdefault("source", "llm")

        # Validate function exists
        if not has_function(parsed_response["function"]):
            logger.error(f"Unknown function requested: {parsed_response['function']}")
            raise ValueError(f"Unknown function: {parsed_response['function']}")

        logger.info(f"Command parsed successfully: {parsed_response['function']}")
        return parsed_response

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response as JSON: {e}")
        return parser_error("parse_error", f"Failed to parse AI response as JSON: {e}")
    except Exception as e:
        logger.error(f"AI processing failed: {e}", exc_info=True)
        return parser_error("ai_error", f"AI processing failed: {e}")


def validate_parsed_command(parsed_command: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate a parsed command structure and arguments.

    Args:
        parsed_command: The parsed command dictionary

    Returns:
        Tuple of (is_valid, error_message)
    """
    if "error" in parsed_command:
        return True, None  # Error responses are valid

    if "function" not in parsed_command:
        return False, "Missing 'function' field"

    function_name = parsed_command["function"]

    # Check if function exists
    if not has_function(function_name):
        return False, f"Unknown function: {function_name}"

    # Get function signature for validation
    func = get_function(function_name)
    sig = inspect.signature(func)

    args = parsed_command.get("args", {})

    # Check required parameters
    for param_name, param in sig.parameters.items():
        if param.default == inspect.Parameter.empty and param_name not in args:
            return False, f"Missing required parameter: {param_name}"

    return True, None
