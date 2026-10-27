import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import db
from .explain import explain

LOCAL_HOST = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")
LOCAL_ORIGIN = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")


def make_server(conn, host="127.0.0.1", port=8765, client=None):
    page = resources.files("decomp_notes").joinpath("ui.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status=200):
            self._send(status, json.dumps(obj).encode(), "application/json")

        def _allowed(self):
            if not LOCAL_HOST.match(self.headers.get("Host", "")):
                self._json({"error": "bad host"}, 403)
                return False
            origin = self.headers.get("Origin")
            if origin is not None and not LOCAL_ORIGIN.match(origin):
                self._json({"error": "bad origin"}, 403)
                return False
            return True

        def do_POST(self):
            # drain the body so the client sees our reply, not a reset
            self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 1 << 20))
            if not self._allowed():
                return
            ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                self._json({"error": "content-type must be application/json"}, 415)
            else:
                self._json({"error": "not found"}, 404)

        def do_GET(self):
            if not self._allowed():
                return
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/":
                self._send(200, page, "text/html; charset=utf-8")
            elif url.path == "/api/functions":
                self._json(db.list_functions(conn, q.get("q", "")))
            elif url.path == "/api/search":
                self._json(db.search(conn, q.get("q", "")))
            elif url.path == "/api/function":
                detail = db.function_detail(conn, q.get("id", ""))
                if detail is None:
                    self._json({"error": "no such function"}, 404)
                else:
                    self._json(detail)
            elif url.path == "/api/explain":
                try:
                    self._json(explain(conn, q.get("id", ""), client))
                except KeyError:
                    self._json({"error": "no such function"}, 404)
            else:
                self._json({"error": "not found"}, 404)

        def log_message(self, *args):
            pass

    return HTTPServer((host, port), Handler)
