import re


def check_sql_injection(response):
    try:
        # Checking for common SQL Injection patterns
        sql_injection_patterns = [
            r'\'\s*or\s*\'\'=\'',
            r'\" OR \"\"=',
            r'; DROP TABLE',
            r'1 OR 1=1',
            r'1; DROP TABLE users',
            r'\' OR 1=1; --',
            r'UNION ALL SELECT',
            r'1; INSERT INTO users'
        ]

        vulnerabilities = []

        for pattern in sql_injection_patterns:
            if re.search(pattern, response.text):
                vulnerabilities.append(pattern)

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
