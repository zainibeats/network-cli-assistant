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
from src.utils import get_prompt

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
    model = genai.GenerativeModel('gemini-pro')
    
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
