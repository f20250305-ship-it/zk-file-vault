"""
Automated Cryptographic & API Test Suite for Zero-Knowledge File Vault
Compatible with both pytest and python -m unittest.
"""

import os
import shutil
import tempfile
import time
import unittest

from backend.storage import VaultStorage


class TestVaultStorage(unittest.TestCase):
    def setUp(self):
        # Create a isolated temporary vault storage directory
        self.test_dir = tempfile.mkdtemp(prefix="zk_vault_test_")
        self.storage = VaultStorage(storage_dir=self.test_dir)

        # Mock client-side encrypted test payload
        self.mock_ciphertext = "8f3a9e1b4c7d0e2f5a6b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
        self.mock_iv = "MDEyMzQ1Njc4OTAx"       # 12 bytes base64
        self.mock_salt = "c2FsdF9zYWx0X3NhbHQ="  # 16 bytes base64
        self.mock_filename = "c2VjcmV0X2RvYy5wZGY="

    def tearDown(self):
        # Clean up temporary test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_store_and_retrieve_success(self):
        """Verify client-encrypted blob can be stored and retrieved intact."""
        res = self.storage.store_blob(
            ciphertext_b64=self.mock_ciphertext,
            iv_b64=self.mock_iv,
            salt_b64=self.mock_salt,
            encrypted_filename_b64=self.mock_filename,
            expires_in_seconds=3600,
            max_downloads=5,
        )

        self.assertTrue(res["success"])
        file_id = res["file_id"]
        self.assertEqual(len(file_id), 32)  # 16 bytes hex

        status, payload = self.storage.retrieve_blob(file_id)
        self.assertEqual(status, "OK")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["ciphertext"], self.mock_ciphertext)
        self.assertEqual(payload["iv"], self.mock_iv)
        self.assertEqual(payload["salt"], self.mock_salt)
        self.assertEqual(payload["remaining_downloads"], 4)
        self.assertFalse(payload["burned"])

    def test_burn_after_reading(self):
        """Verify single-use links self-destruct immediately after first download."""
        res = self.storage.store_blob(
            ciphertext_b64=self.mock_ciphertext,
            iv_b64=self.mock_iv,
            salt_b64=self.mock_salt,
            encrypted_filename_b64=self.mock_filename,
            expires_in_seconds=3600,
            max_downloads=1,  # Burn after reading
        )
        file_id = res["file_id"]

        # First retrieval should succeed and indicate burn
        status1, payload1 = self.storage.retrieve_blob(file_id)
        self.assertEqual(status1, "OK")
        self.assertTrue(payload1["burned"])
        self.assertEqual(payload1["remaining_downloads"], 0)

        # Second retrieval MUST return NOT_FOUND (file was shredded from disk)
        status2, payload2 = self.storage.retrieve_blob(file_id)
        self.assertEqual(status2, "NOT_FOUND")
        self.assertIsNone(payload2)

    def test_metadata_inspection_does_not_burn_file(self):
        """Querying metadata must never consume a download counter or burn the file."""
        res = self.storage.store_blob(
            ciphertext_b64=self.mock_ciphertext,
            iv_b64=self.mock_iv,
            salt_b64=self.mock_salt,
            encrypted_filename_b64=self.mock_filename,
            expires_in_seconds=3600,
            max_downloads=1,
        )
        file_id = res["file_id"]

        status_meta, meta = self.storage.get_metadata(file_id)
        self.assertEqual(status_meta, "OK")
        self.assertEqual(meta["remaining_downloads"], 1)

        # File must still be intact and retrievable
        status_get, payload = self.storage.retrieve_blob(file_id)
        self.assertEqual(status_get, "OK")
        self.assertTrue(payload["burned"])

    def test_expiration_and_purge(self):
        """Files past expiration timestamp must be rejected and purged."""
        res = self.storage.store_blob(
            ciphertext_b64=self.mock_ciphertext,
            iv_b64=self.mock_iv,
            salt_b64=self.mock_salt,
            encrypted_filename_b64=self.mock_filename,
            expires_in_seconds=60,
            max_downloads=5,
        )
        file_id = res["file_id"]

        # Artificially alter expiration to 10 seconds in the past
        _, meta_path = self.storage._get_paths(file_id)
        import json
        with open(meta_path, "r") as f:
            meta = json.load(f)
        meta["expires_at"] = time.time() - 10
        with open(meta_path, "w") as f:
            json.dump(meta, f)

        # Attempt to retrieve expired file
        status, payload = self.storage.retrieve_blob(file_id)
        self.assertEqual(status, "EXPIRED")
        self.assertIsNone(payload)

    def test_path_traversal_protection(self):
        """Attempting directory traversal in file IDs must raise ValueError or return NOT_FOUND safely."""
        with self.assertRaises(ValueError):
            self.storage._get_paths("../../../etc/passwd")

        with self.assertRaises(ValueError):
            self.storage._get_paths("invalid-file-id!@#$")

        status, payload = self.storage.retrieve_blob("../../../etc/passwd")
        self.assertEqual(status, "NOT_FOUND")
        self.assertIsNone(payload)

    def test_zero_knowledge_storage_contains_no_plaintext(self):
        """Verify on-disk blob only contains ciphertext and zero plaintext."""
        res = self.storage.store_blob(
            ciphertext_b64=self.mock_ciphertext,
            iv_b64=self.mock_iv,
            salt_b64=self.mock_salt,
            encrypted_filename_b64=self.mock_filename,
            expires_in_seconds=3600,
        )
        blob_path, _ = self.storage._get_paths(res["file_id"])
        with open(blob_path, "r") as f:
            content = f.read()

        self.assertEqual(content, self.mock_ciphertext)
        self.assertNotIn("secret_doc.pdf", content)


if __name__ == "__main__":
    unittest.main()
