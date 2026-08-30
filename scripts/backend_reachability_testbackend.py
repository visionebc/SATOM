#!/usr/bin/env python3
"""Minimal real backend for the backend_reachability self-test.

HLTHCK_HTTP on fortiweb13 sends `HEAD /` and matches response-code 200, so
that is what this answers -- on every path, with no body. Anything cleverer
would make a failing health check ambiguous between "the box cannot reach me"
and "my handler said 404".
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self, body=b""):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._ok()

    def do_GET(self):
        self._ok(b"satom backend_reachability self-test: REAL backend\n")

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))


ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
