"""
Vault Configuration Module
Defines storage paths, cryptographic limits, and expiration rules.
"""

import os

# Project Roots
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(PROJECT_ROOT, "data", "vault")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

# Server settings
HOST = "0.0.0.0"
PORT = 8080

# Security limits
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_EXPIRATION_SECONDS = 86400    # 24 Hours
MAX_EXPIRATION_SECONDS = 7 * 86400    # 7 Days
MIN_EXPIRATION_SECONDS = 60           # 1 Minute

# Auto-cleanup interval
CLEANUP_INTERVAL_SECONDS = 30

# Ensure storage directory exists
os.makedirs(STORAGE_DIR, exist_ok=True)
