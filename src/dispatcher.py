# src/dispatcher.py

"""
The "brain" of the assistant.

This module is responsible for interpreting the user's natural language
input and mapping it to a structured function call.
"""

import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
import inspect
from . import core_functions


def get_prompt():
    # Get all functions from the core_functions module
    # and format them for the Gemini prompt
    core_function_specs = []
    for name, func in inspect.getmembers(core_functions, inspect.isfunction):
        # Get the function signature and docstring
        signature = inspect.signature(func)
        docstring = inspect.getdoc(func)
        
        # Add the function spec to the list
        core_function_specs.append(
            f"Function: {name}{signature}\n\"\"\"{docstring}\"\"\""
        )

    # Join all function specs into a single string
    core_functions_str = "\n\n".join(core_function_specs)

    # Return the full prompt
    return f"""You are the "brain" of a network CLI assistant.

Your task is to translate a user's natural language request into a structured JSON object that calls a specific function.

When a user provides a hostname that appears to be incomplete (e.g., 'google', 'github'), you should infer the most likely top-level domain (TLD) and complete it (e.g., 'google.com', 'github.com').

You have access to the following functions:

{core_functions_str}

Respond with ONLY the JSON object, nothing else.

Here is an example:
User request: 'what is the ip for google'
Your JSON response:
{{
  "function": "dns_lookup",
  "args": {{
    "host": "google.com"
  }}
}}

The user's request will be provided after the '>>>'.

>>> """

load_dotenv()

def parse_command(user_input: str) -> dict:
    """
    Parses natural language and maps it to a core function call using the Gemini API.

    Args:
        user_input: The raw string from the user.

    Returns:
        A dictionary representing the function to call and its arguments.
        Returns an empty dictionary if no command could be parsed.
    """
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    prompt = get_prompt()
    full_prompt = f"{prompt}{user_input}"
    
    try:
        response = model.generate_content(full_prompt)
        
        # Clean up the response
        text_response = response.text.strip()
        # Remove markdown code block formatting if present
        if text_response.startswith('```json'):
            text_response = text_response[7:-3].strip()
        
        # Parse the JSON string into a Python dictionary
        return json.loads(text_response)
    except Exception as e:
        print(f"Error parsing command: {e}")
        return {}
