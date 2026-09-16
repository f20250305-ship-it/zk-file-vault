# 🛡️ ZeroVault: Zero-Knowledge Secure File Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Security Standard](https://img.shields.io/badge/Cipher-AES--256--GCM-00f2fe)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Architecture](https://img.shields.io/badge/Architecture-Zero--Knowledge-00e676)](#-cryptographic-architecture--threat-model)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)](#-automated-testing)

An enterprise-grade, **Zero-Knowledge End-to-End Encrypted (E2EE)** ephemeral file storage and secure sharing platform. Files are encrypted client-side inside the browser using the **WebCrypto API** before transmission. The server operates as a **blind storage engine**—it never sees, handles, or stores plaintext files or decryption keys.

---

## 🔒 Cryptographic Architecture & Threat Model

```mermaid
sequenceDiagram
    autonumber
    actor U as Uploader (Client Browser)
    participant B as WebCrypto API
    participant S as Vault Storage Server (Blind)
    actor R as Recipient (Client Browser)

    Note over U,B: Phase 1: Client-Side Encryption
    U->>B: Select file + choose Expiration & Burn Limit
    B->>B: Generate cryptographically random 256-bit AES key & 96-bit IV
    B->>B: Encrypt file & filename via AES-256-GCM (128-bit Auth Tag)
    B->>S: POST /api/vault/upload (Blinded Ciphertext, IV, Salt, TTL)
    Note over S: Server stores BLIND ciphertext only.<br/>Server NEVER receives the decryption key!
    S-->>B: Returns { file_id: "3a9f..." }
    B-->>U: Generates Share Link: https://.../d/3a9f...#key=8f3b...

    Note over U,R: Phase 2: Out-of-band Secure Sharing (RFC 3986 Anchor)
    U->>R: Shares URL with #key fragment (fragment is NEVER sent to server)

    Note over R,B: Phase 3: Client-Side Decryption & Verification
    R->>B: Opens Vault link
    B->>S: GET /api/vault/file/3a9f...
    S->>S: Increment download counter (Self-destruct if limit reached)
    S-->>B: Returns Ciphertext + IV
    B->>B: Reads #key from URL fragment (never touched network)
    B->>B: Decrypts & verifies GCM authentication tag in memory
    B-->>R: Triggers direct browser download of original verified file
```

---

## 🌟 Key Security Features

1. **Client-Side Authenticated Encryption (AES-256-GCM)**:
   - Uses the native browser `window.crypto.subtle` API.
   - Every file is encrypted with a unique 256-bit key and 96-bit Initialization Vector (IV).
   - The 128-bit Galois authentication tag guarantees data integrity and detects any Man-In-The-Middle (MITM) tampering or bit-flipping.

2. **RFC 3986 URL Hash Key Isolation**:
   - The decryption key is embedded in the URL fragment (`#key=...`).
   - Per RFC 3986, URL fragments are parsed **exclusively** on the client and are **never** transmitted across the wire in HTTP request headers.

3. **Passphrase-Derived Key Mode (PBKDF2-HMAC-SHA256)**:
   - Option to protect links with a personal passphrase.
   - Derives keys using 100,000 rounds of PBKDF2 with a 128-bit cryptographically random salt per file.

4. **Burn-After-Reading & Self-Destruction**:
   - Single-use downloads: files are securely shredded from disk immediately upon first retrieval.
   - Configurable Time-To-Live (TTL): 10 minutes, 1 hour, 24 hours, or 7 days.

5. **Cryptographic Data Shredding**:
   - Before unlinking expired or burned files from disk, the server overwrites the storage blocks with random entropy (`secrets.token_bytes`) to thwart filesystem block recovery.

6. **Zero External Dependencies Required**:
   - Ships with an asynchronous, multi-threaded standard library server (`http.server.ThreadingHTTPServer`), meaning it can be run immediately on any system with Python 3.10+ without running `pip install`!
   - Also includes a full FastAPI ASGI application (`backend/asgi_app.py`) for enterprise container deployments.

---

## 🛡️ Threat Model & Guarantees

| Attack Scenario | Vault Protection Mechanism | Outcome |
| :--- | :--- | :--- |
| **Complete Server Compromise** | Server only holds blinded ciphertext blobs; never receives keys or passphrases. | **No Plaintext Leakage**: Attacker cannot decrypt any stored files without client-side keys. |
| **Network Eavesdropping / ISP Interception** | Key is anchored in the URL hash (`#`); HTTPS protects transport. | **Key Protected**: URL hash fragments are never sent across HTTP request lines. |
| **Payload Tampering / Bit-flipping** | AES-GCM 128-bit authentication tag validation. | **Detected & Blocked**: WebCrypto rejects modified ciphertext with cryptographic verification failure. |
| **Server Cold-Disk Recovery** | Secure random overwriting (`secrets.token_bytes`) prior to unlinking. | **Unrecoverable**: Data blocks cannot be reconstructed from raw storage drives. |

---

## 🚀 Quick Start

### 1. Run Locally (Zero Dependencies!)
Run directly using Python's built-in runtime:

```bash
# Clone the repository
git clone https://github.com/f20250305-ship-it/zk-file-vault.git
cd zk-file-vault

# Start the Vault
python run_vault.py
```

Your browser will automatically open to:
```
http://localhost:8080
```

---

## 📡 REST API Reference

### `POST /api/vault/upload`
Uploads a client-encrypted ciphertext blob.
- **Request Body (JSON)**:
  ```json
  {
    "ciphertext": "<base64_encoded_ciphertext>",
    "iv": "<base64_encoded_12_byte_iv>",
    "salt": "<base64_encoded_16_byte_salt>",
    "encrypted_filename": "<base64_encoded_filename_meta>",
    "expires_in": 86400,
    "max_downloads": 1
  }
  ```
- **Response (201 Created)**:
  ```json
  {
    "success": true,
    "file_id": "8f3a9e1b4c7d0e2f5a6b8c9d0e1f2a3b",
    "expires_at": 1789504800.0,
    "max_downloads": 1,
    "is_burn_after_reading": true
  }
  ```

### `GET /api/vault/file/{file_id}`
Retrieves ciphertext and increments download counter (triggers burn if threshold reached).

### `GET /api/vault/meta/{file_id}`
Non-destructive metadata inspection (does NOT consume download count).

### `GET /api/vault/stats`
Telemetry regarding active encrypted blobs and total purged/shredded files.

---

## 🧪 Automated Testing

Run the included automated cryptographic and storage unit tests:

```bash
python -m unittest tests/test_vault_api.py
```

---

## 📄 License
Released under the [MIT License](LICENSE). Built for high-assurance cybersecurity and privacy research.
