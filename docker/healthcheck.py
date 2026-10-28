from http.client import HTTPConnection
from entrypoint import get_web_address


def main():
    host, port = get_web_address()
    if host == "0.0.0.0":
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    connection = HTTPConnection(host, port, timeout=3)
    try:
        connection.request("GET", "/login")
        response = connection.getresponse()
        if not 200 <= response.status < 400:
            raise SystemExit(1)
    finally:
        connection.close()


if __name__ == "__main__":
    main()
