#!/usr/bin/env python3
"""
Zenith-Sentry Web Server
Lightweight HTTPS server using Python's built-in http.server + ssl
Serves the static HTML/CSS/JS UI and reverse-proxies API calls to the FastAPI backend.

Usage:
    python3 server.py [--port 8443] [--api http://localhost:8000]

Generates a self-signed TLS cert automatically if none is found.
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
INDEX_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg":  "image/svg+xml",
    ".png":  "image/png",
    ".ico":  "image/x-icon",
    ".woff2": "font/woff2",
    ".woff":  "font/woff",
}

API_BACKEND = "http://localhost:8000"                   

CERT_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE  = os.path.join(CERT_DIR, "server.key")

def ensure_tls_cert():
    """Generate a self-signed TLS certificate if one doesn't exist."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    os.makedirs(CERT_DIR, exist_ok=True)
    print("[TLS] Generating self-signed certificate...")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-nodes",
            "-subj", "/C=US/ST=Local/L=Local/O=ZenithSentry/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"
        ], check=True, capture_output=True)
        print(f"[TLS] Certificate created: {CERT_FILE}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[TLS] WARNING: Could not generate certificate: {e}")
        print("[TLS] Falling back to HTTP mode on port 8080.")
        return False
    return True

def make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx

class ZenithHandler(BaseHTTPRequestHandler):
    log_message = lambda self, fmt, *args: None                                

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_OPTIONS(self):
                         
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _handle(self, method):
        path = self.path.split("?")[0]
        query = self.path[len(path):]                        

        if path.startswith("/api/"):
            self._proxy_api(method, path, query)
            return

        if method != "GET":
            self._error(405, "Method Not Allowed")
            return

        if path == "/" or path == "/index.html":
            self._serve_file(INDEX_FILE)
            return

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            file_path = os.path.join(STATIC_DIR, rel)
            if os.path.isfile(file_path):
                self._serve_file(file_path)
            else:
                self._error(404, f"Not found: {path}")
            return

        self._serve_file(INDEX_FILE)

    def _proxy_api(self, method, path, query):
        url = API_BACKEND + path + query
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None

        try:
            req = urllib.request.Request(
                url, data=body, method=method,
                headers={"Content-Type": self.headers.get("Content-Type", "application/json")}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                ct   = resp.headers.get("Content-Type", "application/json")
                self.send_response(resp.status)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self._cors_headers()
                self.end_headers()
                self.wfile.write(data)

        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)

        except Exception as exc:
            payload = json.dumps({"error": str(exc), "detail": "Backend unreachable"}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(payload)

    def _serve_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self._error(404, "File not found")
            return

        ext  = os.path.splitext(file_path)[1].lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")

        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
                          
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        if self.server.using_tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "connect-src 'self';"
        )
        self.end_headers()
        self.wfile.write(data)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _error(self, code, msg):
        body = json.dumps({"error": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def main():
    parser = argparse.ArgumentParser(description="Zenith-Sentry Web UI Server")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS port (default: 8443)")
    parser.add_argument("--api",  type=str, default="http://localhost:8000", help="FastAPI backend URL")
    parser.add_argument("--http", action="store_true", help="Force HTTP mode (no TLS)")
    args = parser.parse_args()

    global API_BACKEND
    API_BACKEND = args.api.rstrip("/")

    using_tls = False

    if not args.http:
        tls_ok = ensure_tls_cert()
        if tls_ok:
            using_tls = True
        else:
            args.port = 8080
            print("[SERVER] Falling back to HTTP on port 8080")

    server = HTTPServer(("0.0.0.0", args.port), ZenithHandler)
    server.using_tls = using_tls

    if using_tls:
        ctx = make_ssl_context()
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    print(f"""
╔══════════════════════════════════════════════════╗
║        ZENITH-SENTRY COMMAND CENTER              ║
╠══════════════════════════════════════════════════╣
║  UI     : {proto}://localhost:{args.port:<5}               ║
║  API    : {API_BACKEND:<40} ║
║  TLS    : {'ENABLED (self-signed)' if using_tls else 'DISABLED (HTTP mode)'}               ║
╚══════════════════════════════════════════════════╝

  Press Ctrl+C to stop.
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
        server.shutdown()

if __name__ == "__main__":
    main()
