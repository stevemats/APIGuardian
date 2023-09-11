import re


def check_command_injection(response):
    try:
        # Checking for common Command Injection patterns
        command_injection_patterns = [
            r';\s*ping\s',
            r';\s*ls\s',
            r';\s*cat\s',
            r';\s*rm\s',
            r'|',
            r'&&',
            r';\s*curl\s'
        ]

        vulnerabilities = []

        for pattern in command_injection_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerabilities.append(pattern)

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
