"""
Zero-Knowledge Vault HTTP Server
Zero-dependency, multi-threaded HTTP server providing:
1. REST API endpoints for encrypted blob storage & retrieval.
2. Static asset delivery for the Cyberpunk Security UI.
"""

import json
import mimetypes
import os
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from backend.config import FRONTEND_DIR, HOST, PORT, MAX_PAYLOAD_SIZE
from backend.storage import storage
from backend.cleaner import cleaner


class VaultHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:;")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, status_code: int = 400, code: str = "ERROR"):
        self._send_json({"success": False, "code": code, "error": message}, status_code)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # API Endpoints
        if path == "/api/vault/stats":
            self._send_json(storage.get_stats())
            return

        if path.startswith("/api/vault/meta/"):
            file_id = path[len("/api/vault/meta/"):]
            status, meta = storage.get_metadata(file_id)
            if status == "OK":
                self._send_json({"success": True, "metadata": meta})
            elif status == "EXPIRED":
                self._send_error_json("This file has expired and been shredded.", 410, "EXPIRED")
            else:
                self._send_error_json("File not found or already burned.", 404, "NOT_FOUND")
            return

        if path.startswith("/api/vault/file/"):
            file_id = path[len("/api/vault/file/"):]
            status, payload = storage.retrieve_blob(file_id)
            if status == "OK":
                self._send_json({"success": True, "payload": payload})
            elif status == "EXPIRED":
                self._send_error_json("File has expired and been securely destroyed.", 410, "EXPIRED")
            else:
                self._send_error_json("File not found or already burned after reading.", 404, "NOT_FOUND")
            return

        # Direct link route: /d/<file_id> or /decrypt/<file_id> -> serve index.html
        if path.startswith("/d/") or path.startswith("/decrypt/"):
            self.path = "/index.html"
            return super().do_GET()

        # Static assets
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/vault/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > MAX_PAYLOAD_SIZE:
                self._send_error_json("Payload exceeds 50MB maximum limit.", 413, "PAYLOAD_TOO_LARGE")
                return

            try:
                raw_body = self.rfile.read(content_length)
                body = json.loads(raw_body.decode("utf-8"))
            except Exception as e:
                self._send_error_json(f"Malformed JSON payload: {e}", 400, "BAD_REQUEST")
                return

            ciphertext = body.get("ciphertext")
            iv = body.get("iv")
            salt = body.get("salt", "")
            encrypted_filename = body.get("encrypted_filename", "")
            expires_in = body.get("expires_in", 86400)
            max_downloads = body.get("max_downloads", 1)

            if not ciphertext or not iv:
                self._send_error_json("Missing required cryptographic fields: ciphertext, iv", 400, "MISSING_FIELDS")
                return

            try:
                result = storage.store_blob(
                    ciphertext_b64=ciphertext,
                    iv_b64=iv,
                    salt_b64=salt,
                    encrypted_filename_b64=encrypted_filename,
                    expires_in_seconds=expires_in,
                    max_downloads=max_downloads,
                )
                self._send_json(result, 201)
            except Exception as e:
                self._send_error_json(f"Storage error: {e}", 500, "INTERNAL_ERROR")
            return

        self._send_error_json("Endpoint not found", 404, "NOT_FOUND")

    def log_message(self, format, *args):
        # Clean logging format
        print(f"[Vault HTTP] {self.address_string()} - {format % args}")


def start_server(host: str = HOST, port: int = PORT):
    # Start auto-purge cleaner thread
    cleaner.start()

    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, VaultHTTPHandler)
    print(f"\n=========================================================")
    print(f"  ZERO-KNOWLEDGE SECURE FILE VAULT")
    print(f"  AES-256-GCM + PBKDF2 Client-Side Encryption")
    print(f"  Server Running: http://localhost:{port}")
    print(f"=========================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Vault server...")
    finally:
        cleaner.stop()
        httpd.server_close()


if __name__ == "__main__":
    start_server()
