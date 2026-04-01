"""
Password Criteria and Strength Checker
Coded by Sydney Umezurike
Date: April 14, 2025
"""

import re

def sanitize_input(raw_input):
    """
    Clean up the raw input from the user to avoid unwanted control characters.

    Args:
        raw_input (str): The raw text entered by the user.

    Returns:
        str: The cleaned-up input.
    """
    return re.sub(r'[\x00-\x1F\x7F]', '', raw_input)

def check_password_strength(password):
    """
    Check if the password meets the required criteria.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if it passes all checks, False otherwise.
        dict: Dictionary with keys showing which criteria passed.
    """
    criteria = {
        "has_length": False,
        "has_uppercase": False,
        "has_lowercase": False,
        "has_digit": False,
        "has_special": False
    }

    if len(password) >= 16:
        criteria["has_length"] = True
    if re.search(r'[A-Z]', password):
        criteria["has_uppercase"] = True
    if re.search(r'[a-z]', password):
        criteria["has_lowercase"] = True
    if re.search(r'\d', password):
        criteria["has_digit"] = True
    if re.search(r'[!@#$%&]', password):
        criteria["has_special"] = True

    return all(criteria.values()), criteria

def main():
    """
    Run the password checker program.
    """
    try:
        print("=" * 60)
        print("This Password Checker was created by Sydney Umezurike on April 14, 2025.")
        print("=" * 60)

        print("Enter a password to check: ")
        password = input()

        password = sanitize_input(password)

        if not password:
            print("Error: No password provided. Please try again.")
            return

        strong_flag, criteria = check_password_strength(password)

        if strong_flag:
            print("\nStrong password that meets the requirements.")
        else:
            print("\nPassword does not meet requirements. Your PII is at grave risk!")
            print("\nTips to strengthen your password:")

            if not criteria["has_length"]:
                print("- Add more characters (at least 16 total).")
            if not (criteria["has_uppercase"] and criteria["has_lowercase"] and criteria["has_digit"] and criteria["has_special"]):
                print("- Boost complexity with:")
                if not criteria["has_uppercase"]:
                    print("  * An uppercase letter (A-Z)")
                if not criteria["has_lowercase"]:
                    print("  * A lowercase letter (a-z)")
                if not criteria["has_digit"]:
                    print("  * A digit (0-9)")
                if not criteria["has_special"]:
                    print("  * A special character (!, @, #, $, %, &)")

            print("\nPassword tips:")
            print("1. Make it long (16+ characters).")
            print("2. Mix letters, numbers, and symbols.")
            print("3. Keep it unique for each account.")

    except (EOFError, ValueError) as error:
        print(f"An error occurred: {error}")
        print("Please try again.")

if __name__ == "__main__":
    main()
