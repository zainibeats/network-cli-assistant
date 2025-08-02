# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

import os
import json
import re
import google.generativeai as genai
from dotenv import load_dotenv
import inspect
from typing import Dict, List, Tuple, Optional
from . import core_functions





def get_enhanced_prompt():
    """
    Generate a prompt for AI command parsing.
    """
    # Get all functions from the core_functions module
    core_function_specs = []
    for name, func in inspect.getmembers(core_functions, inspect.isfunction):
        # Skip private functions
        if name.startswith('_'):
            continue
            
        signature = inspect.signature(func)
        docstring = inspect.getdoc(func)
        
        core_function_specs.append(
            f"Function: {name}{signature}\n\"\"\"{docstring}\"\"\""
        )

    core_functions_str = "\n\n".join(core_function_specs)

    return f"""You are a network CLI assistant command parser.

Your task is to translate a user's natural language request into a structured JSON object that calls a specific function.

You have access to the following functions:

{core_functions_str}

Respond with ONLY the JSON object, nothing else. If you cannot determine the intent, respond with:
{{"error": "ambiguous"}}

The user's request will be provided after the '>>>'.

>>> """





load_dotenv()


def parse_command(user_input: str) -> dict:
    """
    Enhanced command parser with better networking terminology understanding.

    Args:
        user_input: The raw string from the user.

    Returns:
        A dictionary representing the function to call and its arguments.
        Returns error dict with suggestions if parsing fails.
    """
    if not user_input or not user_input.strip():
        return {
            "error": "empty_input",
            "message": "Please provide a command"
        }
    

    
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = get_enhanced_prompt()
        full_prompt = f"{prompt}{user_input}"
        
        response = model.generate_content(full_prompt)
        
        # Clean up the response
        text_response = response.text.strip()
        if text_response.startswith('```json'):
            text_response = text_response[7:-3].strip()
        elif text_response.startswith('```'):
            # Handle other code block formats
            lines = text_response.split('\n')
            if len(lines) > 2:
                text_response = '\n'.join(lines[1:-1])
        
        # Parse the JSON response
        parsed_response = json.loads(text_response)
        
        # Validate the response structure
        if "error" in parsed_response:
            if parsed_response["error"] == "ambiguous":
                return {
                    "error": "ambiguous",
                    "message": "Command is ambiguous"
                }
        
        # Validate that we have a function and args
        if "function" not in parsed_response:
            raise ValueError("Response missing 'function' field")
        
        if "args" not in parsed_response:
            parsed_response["args"] = {}
        
        # Validate function exists
        if not hasattr(core_functions, parsed_response["function"]):
            raise ValueError(f"Unknown function: {parsed_response['function']}")
        
        return parsed_response
        
    except json.JSONDecodeError as e:
        return {
            "error": "parse_error",
            "message": f"Failed to parse AI response as JSON: {e}"
        }
    except Exception as e:
        return {
            "error": "ai_error", 
            "message": f"AI processing failed: {e}"
        }


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
    if not hasattr(core_functions, function_name):
        return False, f"Unknown function: {function_name}"
    
    # Get function signature for validation
    func = getattr(core_functions, function_name)
    sig = inspect.signature(func)
    
    args = parsed_command.get("args", {})
    
    # Check required parameters
    for param_name, param in sig.parameters.items():
        if param.default == inspect.Parameter.empty and param_name not in args:
            return False, f"Missing required parameter: {param_name}"
    
    return True, None
