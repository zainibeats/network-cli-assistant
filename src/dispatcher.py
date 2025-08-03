# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

import os
import json
import re
import logging
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
        docstring = inspect.getdoc(func) or "No documentation available"
        
        spec = "Function: " + name + str(signature) + "\n\"\"\"" + docstring + "\"\"\""
        core_function_specs.append(spec)

    core_functions_str = "\n\n".join(core_function_specs)

    # Build prompt using string concatenation to avoid f-string issues
    prompt = "You are a network CLI assistant command parser.\n\n"
    prompt += "Your task is to translate a user's natural language request into a structured JSON object that calls a specific function.\n\n"
    prompt += "You have access to the following functions:\n\n"
    prompt += core_functions_str + "\n\n"
    prompt += "IMPORTANT: When users mention domain names without TLDs (like \"google\", \"mullvad\", \"github\"), use your knowledge to provide the correct full domain name:\n"
    prompt += "- \"google\" → \"google.com\"\n"
    prompt += "- \"mullvad\" → \"mullvad.net\"\n"
    prompt += "- \"github\" → \"github.com\"\n"
    prompt += "- \"wikipedia\" → \"wikipedia.org\"\n"
    prompt += "- \"archive\" → \"archive.org\"\n"
    prompt += "- \"reddit\" → \"reddit.com\"\n"
    prompt += "- \"stackoverflow\" → \"stackoverflow.com\"\n"
    prompt += "- etc.\n\n"
    prompt += "Use your training data knowledge of well-known websites and services to determine the correct TLD.\n\n"
    prompt += "NETWORK OPERATIONS: Choose the right function based on user intent:\n\n"
    prompt += "HOST DISCOVERY (finding active IPs):\n"
    prompt += "- For \"what IPs are being used\", \"what hosts are up\", \"what machines are active\": use discover_hosts\n"
    prompt += "- Example: \"what IPs are being used on network 192.168.1.0/24\" → {{\"function\": \"discover_hosts\", \"args\": {{\"network\": \"192.168.1.0/24\"}}}}\n"
    prompt += "- Example: \"what machines are up on 10.0.0.0/16\" → {{\"function\": \"discover_hosts\", \"args\": {{\"network\": \"10.0.0.0/16\"}}}}\n\n"
    prompt += "PORT SCANNING (finding open services):\n"
    prompt += "- For \"what ports are open\", \"scan ports\", \"check services\": use run_nmap_scan\n"
    prompt += "- Example: \"what ports are open on network 192.168.1.0/24\" → {{\"function\": \"run_nmap_scan\", \"args\": {{\"target\": \"192.168.1.0/24\"}}}}\n"
    prompt += "- Example: \"scan ports on 192.168.1.1\" → {{\"function\": \"run_nmap_scan\", \"args\": {{\"target\": \"192.168.1.1\"}}}}\n\n"
    prompt += "Respond with ONLY the JSON object in this exact format:\n"
    prompt += "{{\"function\": \"function_name\", \"args\": {{\"param1\": \"value1\", \"param2\": \"value2\"}}}}\n\n"
    prompt += "For example:\n"
    prompt += "- For \"ping google\": {{\"function\": \"ping\", \"args\": {{\"host\": \"google.com\"}}}}\n"
    prompt += "- For \"what is the ip of mullvad\": {{\"function\": \"dns_lookup\", \"args\": {{\"host\": \"mullvad.net\"}}}}\n"
    prompt += "- For \"lookup DNS for github\": {{\"function\": \"dns_lookup\", \"args\": {{\"host\": \"github.com\"}}}}\n"
    prompt += "- For \"scan ports on 192.168.1.1\": {{\"function\": \"run_nmap_scan\", \"args\": {{\"target\": \"192.168.1.1\"}}}}\n"
    prompt += "- For \"what ports are open on network 192.168.1.0/24\": {{\"function\": \"run_nmap_scan\", \"args\": {{\"target\": \"192.168.1.0/24\"}}}}\n"
    prompt += "- For \"what IPs are being used on network 192.168.1.0/24\": {{\"function\": \"discover_hosts\", \"args\": {{\"network\": \"192.168.1.0/24\"}}}}\n"
    prompt += "- For \"what machines are up on 10.0.0.0/16\": {{\"function\": \"discover_hosts\", \"args\": {{\"network\": \"10.0.0.0/16\"}}}}\n\n"
    prompt += "If you cannot determine the intent, respond with:\n"
    prompt += "{{\"error\": \"ambiguous\"}}\n\n"
    prompt += "The user's request will be provided after the '>>>'.\n\n"
    prompt += ">>> "
    
    return prompt





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
    logger = logging.getLogger("network_cli.dispatcher")
    
    if not user_input or not user_input.strip():
        logger.warning("Empty input received")
        return {
            "error": "empty_input",
            "message": "Please provide a command"
        }
    

    
    try:
        logger.debug(f"Configuring Gemini AI for command parsing")
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = get_enhanced_prompt()
        full_prompt = prompt + user_input
        
        logger.debug(f"Sending request to Gemini AI", extra={
            "input_length": len(user_input),
            "prompt_length": len(full_prompt)
        })
        
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
        
        logger.debug(f"AI response parsed successfully", extra={
            "function": parsed_response.get("function"),
            "args_count": len(parsed_response.get("args", {}))
        })
        
        # Validate the response structure
        if "error" in parsed_response:
            if parsed_response["error"] == "ambiguous":
                logger.warning("AI reported ambiguous command")
                return {
                    "error": "ambiguous",
                    "message": "Command is ambiguous"
                }
        
        # Validate that we have a function and args
        if "function" not in parsed_response:
            logger.error("AI response missing 'function' field")
            raise ValueError("Response missing 'function' field")
        
        if "args" not in parsed_response:
            parsed_response["args"] = {}
        
        # Validate function exists
        if not hasattr(core_functions, parsed_response["function"]):
            logger.error(f"Unknown function requested: {parsed_response['function']}")
            raise ValueError(f"Unknown function: {parsed_response['function']}")
        
        logger.info(f"Command parsed successfully: {parsed_response['function']}")
        return parsed_response
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response as JSON: {e}")
        return {
            "error": "parse_error",
            "message": f"Failed to parse AI response as JSON: {e}"
        }
    except Exception as e:
        logger.error(f"AI processing failed: {e}", exc_info=True)
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
