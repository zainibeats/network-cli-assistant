# src/main.py

"""
Main entry point for the Network CLI Assistant.

This script initializes the application, listens for user input,
and orchestrates the command processing flow.
"""

import json
from . import core_functions
from .dispatcher import parse_command
from .utils import format_output

def main():
    """
    The main function that runs the CLI loop.
    """
    print("Welcome to the Network CLI Assistant!")
    print("Type 'exit' or 'quit' to end the session.")

    while True:
        try:
            user_input = input(">> ")

            if user_input.lower() in ["exit", "quit"]:
                print("Goodbye!")
                break

            if not user_input:
                continue

            # 2. Pass the input to the dispatcher to get a structured command.
            command = parse_command(user_input)

            if not command or "function" not in command:
                print("Sorry, I could not understand that command. Please try again.")
                continue

            # 3. Execute the command using the appropriate core function.
            function_name = command.get("function")
            function_args = command.get("args", {})

            try:
                func_to_call = getattr(core_functions, function_name)
                result = func_to_call(**function_args)
                
                # 4. Print the result to the user in a readable format.
                print(format_output(result))

            except AttributeError:
                print(f"Error: The command '{function_name}' is not a valid function.")
            except TypeError as e:
                print(f"Error executing '{function_name}': {e}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    main()
