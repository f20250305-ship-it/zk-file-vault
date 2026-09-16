#!/usr/bin/env python3
"""
Zero-Knowledge Secure File Vault Launcher
Launches the vault server and automatically opens the user interface.
"""

import sys
import webbrowser
import threading
import time
from backend.server import start_server
from backend.config import PORT, HOST


def open_browser():
    time.sleep(1.2)
    url = f"http://localhost:{PORT}"
    print(f"Opening browser at: {url}")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"Could not open browser automatically: {e}")


def main():
    print("Initializing Zero-Knowledge Secure File Vault...")
    # Launch browser opener in background thread
    threading.Thread(target=open_browser, daemon=True).start()
    # Start server
    start_server(host=HOST, port=PORT)


if __name__ == "__main__":
    main()
