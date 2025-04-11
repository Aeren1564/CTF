import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from util import make_ssl_connection


class MyHTTPSRequestHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request = make_ssl_connection(self.request)
        return super().setup()

    def do_GET(self):
        match self.path:
            case "/":
                status = 200
                content = """
<p>I think my server is haunted.</p>
<p><a href="/flag">Get flag</a></p>
<p><a href="/time">Get current server time</a></p>
"""
            case "/flag":
                status = 404
                content = """
<p>👻👻👻 My flag seems to have been stolen by ghosts...! 👻👻👻</p>
"""
            case "/time":
                status = 200
                content = f"""
<p>Current time: {time.ctime()}</p>
"""
            case _:
                status = 404
                content = """
<h1>404 Not Found</h1>
"""

        raw_content = f"""<!DOCTYPE html>
<html>
<body>{content}</body>
</html>""".encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf8")
        self.send_header("Content-Length", str(len(raw_content)))
        self.end_headers()
        self.wfile.write(raw_content)


httpd = ThreadingHTTPServer(("", 1337), MyHTTPSRequestHandler)
httpd.serve_forever()
