def check_insecure_deserialization(response):
    """
    The function `check_insecure_deserialization` checks if a response contains any patterns related to
    insecure deserialization vulnerabilities.

    :param response: The `response` parameter is expected to be an object that represents the response
    received from a web request. It is assumed to have a `text` attribute that contains the response
    body as a string
    :return: a list of vulnerabilities found in the response.
    """
    try:
        insecure_deserialization_patterns = [
            "java.io.ObjectInputStream",
            "ObjectInputStream.readObject",
            "pickle.loads",
            "java.lang.Runtime.exec",
            "Runtime.getRuntime().exec",
            "os.popen",
            "os.system",
            "os.exec",
        ]

        vulnerabilities = []

        for pattern in insecure_deserialization_patterns:
            if pattern in response.text:
                vulnerabilities.append(pattern)

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
