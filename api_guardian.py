import requests
import time
from modules import sql_injection, xss, command_injection


def scan_api(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        if response.status_code == 200:
            print(f"Scanning API at {url}...")
            # Simulating the scanning process 
            time.sleep(2)

            # Checking against SQL Injection
            sql_injection_result = sql_injection.check_sql_injection(response)

            # Check XSS vuln
            xss_result = xss.check_xss(response)

            # Checking against Command Injection
            command_injection_result = command_injection.check_command_injection(
                response)

            vulnerabilities = []

            if sql_injection_result:
                vulnerabilities.append(
                    ("SQL Injection", "Vulnerability detected."))

            if xss_result:
                vulnerabilities.append(
                    ("Cross-Site Scripting (XSS)", "Vulnerability detected."))

            if command_injection_result:
                vulnerabilities.append(
                    ("Command Injection", "Vulnerability detected."))

            if vulnerabilities:
                print(
                    f"Found {len(vulnerabilities)} potential vulnerabilities:")
                for vulnerability, result in vulnerabilities:
                    print(f"- {vulnerability}: {result}")
            else:
                print("No vulnerabilities found.")
        else:
            print(
                f"Error: Unable to access the API. Status code: {response.status_code}")

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as e:
        print(f"An error occurred: {e}")


def display_help():
    print("\n=== APIGuardian Help ===")
    print("Option 1: Enter URL to scan")
    print("  - Example: http://example.com/api")
    print("Option 2: Prints out the help function")
    print("Option 3: Exits you from the program")


def main():
    print("\n=== Welcome to APIGuardian ===")
    print('''
               __
             .'o '.
            /   .-.\.
           /   (
        ,-/     '-.
       /   )  (    |
      |            /
       \         ;'
     ,.,.\      ;..;;
    ,.-+= )    (-:''
         /,.__.,\.

        <Tool Crafted by Stevemats>
        ''')
    while True:
        print("\nVulnerability Scanner Menu:")
        print("1. Enter URL to scan")
        print("2. Help")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            url = input("Enter the URL to scan: ")
            print("Initiating scan...")
            scan_api(url)
        elif choice == "2":
            print("\n=== APIGuardian Help ===")
            display_help()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
