import requests


def check_response(url, transfer_encodings=None):
    try:
        headers = {}

        # Add Transfer-Encoding to headers if specified
        if transfer_encodings:
            headers["Transfer-Encoding"] = ", ".join(transfer_encodings)

        response = requests.get(url, headers=headers, timeout=10)

        transfer_encoding = response.headers.get("Transfer-Encoding")
        content_encoding = response.headers.get("Content-Encoding")

        print(f"Checking URL: {url}")

        if transfer_encoding:
            print(f"Transfer-Encoding: {transfer_encoding}")
            if "chunked" in transfer_encoding.lower():
                print("Response uses chunked transfer encoding.")
            else:
                print("Response does not use chunked transfer encoding.")
        else:
            print("No Transfer-Encoding found.")

        if content_encoding:
            print(f"Content-Encoding: {content_encoding}")
            if "gzip" in content_encoding.lower():
                print("Response content is gzipped.")
            if "deflate" in content_encoding.lower():
                print("Response content is deflated.")
            if "compress" in content_encoding.lower():
                print("Response content is compressed.")
        else:
            print("No Content-Encoding found.")

    except requests.exceptions.Timeout:
        print("Error: Request timed out.")
    except requests.exceptions.ConnectionError:
        print("Error: Connection failed.")
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL: {e}")
