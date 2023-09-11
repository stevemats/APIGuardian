import requests
import time

from modules import *


def scan_api(url):
    """
    The `scan_api` function scans an API at a given URL for potential vulnerabilities such as SQL
    injection, XSS, command injection, insecure deserialization, and authentication bypass.

    :param url: The `url` parameter is a string that represents the URL of the API that you want to scan
    for vulnerabilities
    """
    try:
        response = requests.get(url)
        response.raise_for_status()

        if response.status_code == 200:
            print(f"Scanning API at {url}...")
            time.sleep(2)

            sql_injection_result = sql_injection.check_sql_injection(response)
            xss_result = xss.check_xss(response)
            command_injection_result = command_injection.check_command_injection(
                response
            )
            insecure_deserialization_result = (
                insecure_deserialization.check_insecure_deserialization(
                    response)
            )
            authentication_bypass_result = (
                authentication_bypass.check_authentication_bypass(response)
            )

            vulnerabilities = []

            vulnerabilities.extend(sql_injection_result)
            vulnerabilities.extend(xss_result)
            vulnerabilities.extend(command_injection_result)
            vulnerabilities.extend(insecure_deserialization_result)
            vulnerabilities.extend(authentication_bypass_result)

            if vulnerabilities:
                print(
                    f"Found {len(vulnerabilities)} potential vulnerabilities:")
                for vulnerability in vulnerabilities:
                    print(f"- {vulnerability}: Vulnerability detected.")
            else:
                print("No vulnerabilities found.")
        else:
            print(
                f"Error: Unable to access the API. Status code: {response.status_code}"
            )

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
    print(
        """
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
        """
    )
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
