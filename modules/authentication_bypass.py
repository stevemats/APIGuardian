import re


def check_authentication_bypass(response):
    """
    The function `check_authentication_bypass` checks if a response contains any patterns indicating an
    authentication bypass vulnerability.

    :param response: The `response` parameter is expected to be an object that represents the response
    received from a web request. It should have a `text` attribute that contains the text content of the
    response
    :return: a list of patterns that match the authentication bypass conditions in the response text.
    """
    try:
        authentication_bypass_patterns = [
            r"admin=true",
            r"authenticated=true",
            r"user=admin",
            r"admin\s*=\s*true",
            r"authenticated\s*=\s*true",
            r"user\s*=\s*admin",
            r"isAdmin\s*:\s*true",
            r"isAuthenticated\s*:\s*true",
            r"role\s*:\s*admin",
            r"access\s*:\s*granted",
        ]

        vulnerabilities = []

        for pattern in authentication_bypass_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerabilities.append(pattern)

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
