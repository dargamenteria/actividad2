import argparse
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class testHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.send_response(200)
        self.wfile.write(bytes("Hello World!!!", "utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, prog=__file__)

    ap.add_argument("--port", action="store", help="Set the listening port")
    ap.add_argument("--host", action="store", help="Set the listening interface")
    p = 8080
    h = "0.0.0.0"

    try:
        args = ap.parse_args()
        if args.port is not None:
            p = args.port
        if args.host is not None:
            h = args.host
        httpServer = HTTPServer((h, int(p)), testHandler)
        httpServer.serve_forever()

    except KeyboardInterrupt:
        print("Server stopped manually")
    finally:
        httpServer.server_close()
        return 0


if __name__ == "__main__":
    sys.exit(main())