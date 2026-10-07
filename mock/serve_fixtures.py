#!/usr/bin/env python3
"""One-shot replay server for the benshu-client CLI smoke test.
Serves the MITM capture fixtures; exits after 60 s of inactivity."""
import http.server, json, os
from http.server import HTTPServer, BaseHTTPRequestHandler

CAP = "/home/ubuntu/benshu/mitm_sandbox/captures"
fixtures = {}
for f in os.listdir(CAP):
    if not f.endswith(".json"):
        continue
    d = json.load(open(f"{CAP}/{f}"))
    fixtures[f"{d['method'].upper()} {d['path']}"] = d


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self._handle("GET", self.path)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._handle("POST", self.path)

    def _handle(self, m, path):
        f = fixtures.get(f"{m} {path}")
        if not f:
            body = json.dumps({"code": 500, "msg": "no fixture", "data": None}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(f.get("status", 200))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f["resp_body"].encode())


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 18443), H)
    srv.timeout = 60
    import time
    deadline = time.time() + 60
    while time.time() < deadline:
        srv.handle_request()
    print("mock session done", flush=True)
