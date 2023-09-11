import re


def check_xss(response):
    try:
        # Simulate vuln detection
        # Eg: Checking for common XSS patterns
        xss_patterns = [
            r'<script>',
            r'onmouseover="alert(1)"',
            r'<img src="javascript:alert(\'XSS\')">',
            r'<a href="javascript:alert(\'XSS\')">Click me</a>',
            r'javascript:alert(\'XSS\')',
            r'"><script>alert(\'XSS\')</script><"',
            r'"><img src=x onerror=alert(\'XSS\')>',
            r'"><svg/onload=alert(\'XSS\')>',
            r'"><iframe src="javascript:alert(\'XSS\')">',
            r'"><body onload=alert(\'XSS\')>'
        ]


        vulnerabilities = []

        for pattern in xss_patterns:
            if re.search(pattern, response.text):
                vulnerabilities.append(pattern)

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
