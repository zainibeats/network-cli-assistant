# src/main.py

"""
Main entry point for the Network CLI Assistant.

This script initializes the application, listens for user input,
and orchestrates the command processing flow.
"""

def main():
    """
    The main function that runs the CLI loop.
    """
    print("Welcome to the Network CLI Assistant!")
    print("Type 'exit' or 'quit' to end the session.")

    while True:
        # 1. Prompt the user for a natural language command.
        #    (e.g., "show me port status on server X")
        user_input = input(">> ")

        if user_input.lower() in ["exit", "quit"]:
            print("Goodbye!")
            break

        # 2. Pass the input to the dispatcher to get a structured command.
        #    (This is where the "AI" part will live)
        #    For now, we can imagine it returns a dictionary.
        #    e.g., {'command': 'run_command', 'host': 'server X', 'cmd': 'netstat -tulnp'}

        # 3. Execute the command using the appropriate core function.

        # 4. Print the result to the user in a readable format.

        print(f"Received: {user_input}") # Placeholder

if __name__ == "__main__":
    main()
