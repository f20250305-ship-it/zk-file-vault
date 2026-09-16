"""
Vault Storage Engine
Handles atomic writes, metadata tracking, download limits, and burn-after-reading.
Strictly zero-knowledge: only blinded ciphertext is stored.
"""

import json
import os
import secrets
import threading
import time
from typing import Optional, Dict, Any, Tuple
from backend.config import STORAGE_DIR, DEFAULT_EXPIRATION_SECONDS, MAX_EXPIRATION_SECONDS, MIN_EXPIRATION_SECONDS


class VaultStorage:
    def __init__(self, storage_dir: str = STORAGE_DIR):
        self.storage_dir = storage_dir
        self.lock = threading.Lock()
        self.total_purged = 0
        os.makedirs(self.storage_dir, exist_ok=True)

    def _get_paths(self, file_id: str) -> Tuple[str, str]:
        # Validate file_id is safe hex to prevent directory traversal
        if not file_id or not all(c in "0123456789abcdefABCDEF" for c in file_id):
            raise ValueError("Invalid file ID format.")
        blob_path = os.path.join(self.storage_dir, f"{file_id}.blob")
        meta_path = os.path.join(self.storage_dir, f"{file_id}.meta.json")
        return blob_path, meta_path

    def store_blob(
        self,
        ciphertext_b64: str,
        iv_b64: str,
        salt_b64: str,
        encrypted_filename_b64: str,
        expires_in_seconds: int = DEFAULT_EXPIRATION_SECONDS,
        max_downloads: int = 1,
    ) -> Dict[str, Any]:
        """
        Stores an encrypted ciphertext blob with expiration metadata.
        """
        if not ciphertext_b64 or not iv_b64:
            raise ValueError("Ciphertext and IV are required.")

        # Bound expiration
        expires_in = max(MIN_EXPIRATION_SECONDS, min(int(expires_in_seconds), MAX_EXPIRATION_SECONDS))
        max_dl = max(0, int(max_downloads))

        file_id = secrets.token_hex(16)
        blob_path, meta_path = self._get_paths(file_id)

        now = time.time()
        expires_at = now + expires_in

        meta = {
            "file_id": file_id,
            "iv": iv_b64,
            "salt": salt_b64,
            "encrypted_filename": encrypted_filename_b64,
            "created_at": now,
            "expires_at": expires_at,
            "max_downloads": max_dl,
            "download_count": 0,
            "size_bytes": len(ciphertext_b64),
        }

        with self.lock:
            # Atomic file write for blob
            temp_blob = f"{blob_path}.tmp"
            with open(temp_blob, "w", encoding="utf-8") as f:
                f.write(ciphertext_b64)
            os.replace(temp_blob, blob_path)

            # Atomic file write for meta
            temp_meta = f"{meta_path}.tmp"
            with open(temp_meta, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            os.replace(temp_meta, meta_path)

        return {
            "success": True,
            "file_id": file_id,
            "expires_at": expires_at,
            "expires_in_seconds": expires_in,
            "max_downloads": max_dl,
            "is_burn_after_reading": max_dl == 1,
        }

    def retrieve_blob(self, file_id: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Retrieves the encrypted payload and increments download count.
        If max_downloads is reached (e.g. burn-after-reading), the file is shredded from disk.
        Returns (status_code, payload_dict)
        Statuses: 'OK', 'NOT_FOUND', 'EXPIRED', 'BURNED'
        """
        try:
            blob_path, meta_path = self._get_paths(file_id)
        except ValueError:
            return "NOT_FOUND", None

        with self.lock:
            if not os.path.exists(blob_path) or not os.path.exists(meta_path):
                return "NOT_FOUND", None

            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                return "NOT_FOUND", None

            # Check expiration
            now = time.time()
            if now > meta.get("expires_at", 0):
                self._delete_files_unsafe(blob_path, meta_path)
                self.total_purged += 1
                return "EXPIRED", None

            # Read ciphertext
            try:
                with open(blob_path, "r", encoding="utf-8") as f:
                    ciphertext_b64 = f.read()
            except Exception:
                return "NOT_FOUND", None

            # Increment download count
            meta["download_count"] = meta.get("download_count", 0) + 1
            max_dl = meta.get("max_downloads", 1)
            burned = False

            # Check if self-destruct condition triggered
            if max_dl > 0 and meta["download_count"] >= max_dl:
                self._delete_files_unsafe(blob_path, meta_path)
                self.total_purged += 1
                burned = True
            else:
                # Update meta on disk
                temp_meta = f"{meta_path}.tmp"
                with open(temp_meta, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
                os.replace(temp_meta, meta_path)

            remaining = 0 if burned else (max_dl - meta["download_count"] if max_dl > 0 else -1)

            payload = {
                "file_id": file_id,
                "ciphertext": ciphertext_b64,
                "iv": meta["iv"],
                "salt": meta.get("salt", ""),
                "encrypted_filename": meta.get("encrypted_filename", ""),
                "burned": burned,
                "remaining_downloads": remaining,
            }
            return "OK", payload

    def get_metadata(self, file_id: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Returns public non-destructive metadata about a file.
        Does NOT increment download count or burn file.
        """
        try:
            blob_path, meta_path = self._get_paths(file_id)
        except ValueError:
            return "NOT_FOUND", None

        with self.lock:
            if not os.path.exists(blob_path) or not os.path.exists(meta_path):
                return "NOT_FOUND", None

            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                return "NOT_FOUND", None

            now = time.time()
            if now > meta.get("expires_at", 0):
                self._delete_files_unsafe(blob_path, meta_path)
                self.total_purged += 1
                return "EXPIRED", None

            max_dl = meta.get("max_downloads", 1)
            dl_count = meta.get("download_count", 0)
            remaining = max(0, max_dl - dl_count) if max_dl > 0 else -1

            return "OK", {
                "file_id": file_id,
                "expires_at": meta["expires_at"],
                "expires_in_seconds": max(0, int(meta["expires_at"] - now)),
                "max_downloads": max_dl,
                "remaining_downloads": remaining,
                "is_burn_after_reading": max_dl == 1,
                "size_bytes": meta.get("size_bytes", 0),
                "has_salt": bool(meta.get("salt")),
            }

    def purge_expired(self) -> int:
        """
        Background task to remove all expired blobs and metadata.
        Returns count of purged items.
        """
        purged = 0
        now = time.time()
        with self.lock:
            try:
                files = os.listdir(self.storage_dir)
            except Exception:
                return 0

            meta_files = [f for f in files if f.endswith(".meta.json")]
            for mf in meta_files:
                file_id = mf[:-10]
                meta_path = os.path.join(self.storage_dir, mf)
                blob_path = os.path.join(self.storage_dir, f"{file_id}.blob")

                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if now > meta.get("expires_at", 0):
                        self._delete_files_unsafe(blob_path, meta_path)
                        purged += 1
                except Exception:
                    self._delete_files_unsafe(blob_path, meta_path)
                    purged += 1

            self.total_purged += purged
        return purged

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns active storage telemetry.
        """
        with self.lock:
            try:
                files = os.listdir(self.storage_dir)
                active_meta = len([f for f in files if f.endswith(".meta.json")])
            except Exception:
                active_meta = 0

            return {
                "active_vault_files": active_meta,
                "total_purged_files": self.total_purged,
                "zero_knowledge": True,
                "encryption_standard": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256 (100,000 iter)",
            }

    def _delete_files_unsafe(self, blob_path: str, meta_path: str):
        for path in [blob_path, meta_path]:
            try:
                if os.path.exists(path):
                    # Overwrite file content before removing for data shredding
                    size = os.path.getsize(path)
                    with open(path, "wb") as f:
                        f.write(secrets.token_bytes(min(size, 4096)))
                    os.remove(path)
            except Exception:
                pass


# Global storage instance
storage = VaultStorage()
