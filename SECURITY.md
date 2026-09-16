# Security Policy

## Supported Versions

The ZeroVault team actively maintains security updates and patches for the following versions:

| Version | Supported          | Cryptographic Standard | Notes |
| ------- | ------------------ | ---------------------- | ----- |
| 1.0.x   | :white_check_mark: | AES-256-GCM / PBKDF2   | Current active release |
| < 1.0   | :x:                | —                      | Unsupported legacy versions |

---

## 🛡️ Security Architecture & Invariants

ZeroVault is engineered under a **Zero-Trust / Blind Server** model. All contributors and security researchers must adhere to these core invariants:

1. **Zero Server Knowledge**:
   - The server must **never** receive, parse, log, or persist the 256-bit AES encryption key, user passphrases, or plaintext files.
   - Decryption keys must remain anchored in the URL fragment (`#key=...`) per **RFC 3986**, preventing transmission in HTTP request headers.

2. **Cryptographic Primitives**:
   - **Authenticated Encryption**: Standardized on **AES-256-GCM** (Galois/Counter Mode) with 96-bit unique IVs and 128-bit authentication tags.
   - **Key Derivation**: **PBKDF2-HMAC-SHA256** with 100,000 rounds and a 128-bit cryptographically secure random salt per file.
   - **Randomness**: All IVs, keys, and salts must be generated using cryptographically secure pseudorandom generators (`window.crypto.getRandomValues` in the browser; `secrets.token_bytes` in Python).

3. **Data Shredding & Ephemeral Lifecycle**:
   - Storage blocks must be overwritten with random entropy prior to filesystem unlinking (`shredding`) upon reaching max downloads or TTL expiration.
   - File IDs must be sanitized to prevent directory traversal attacks (`../`).

---

## 🚨 Reporting a Vulnerability

We take the security of ZeroVault seriously. If you discover a security vulnerability or cryptographic weakness, please report it via **Coordinated Vulnerability Disclosure**.

### How to Report
- **Email**: Contact the maintainer directly at [f20250305@dubai.bits-pilani.ac.in](mailto:f20250305@dubai.bits-pilani.ac.in) with the subject `[SECURITY VULNERABILITY] ZeroVault - <Brief Summary>`.
- **GitHub**: You may also submit a private vulnerability advisory via [GitHub Security Advisories](https://github.com/f20250305-ship-it/zk-file-vault/security/advisories/new).

### What to Include
Please provide a detailed report including:
1. **Description**: Clear description of the vulnerability (e.g., cryptographic flaw, injection, timing attack, denial of service).
2. **Steps to Reproduce**: A minimal, reproducible proof-of-concept (PoC) or script.
3. **Impact**: Potential security impact on confidential files, integrity, or users.
4. **Suggested Fix**: Any recommended patches or mitigations (if known).

### Response Timeline
- **Initial Acknowledgment**: Within **48 hours**.
- **Assessment & Triage**: Within **5 business days**.
- **Fix & Public Disclosure**: Coordinated release following patch validation.

---

## 🔍 In-Scope vs. Out-of-Scope

### In-Scope:
- Flaws in client-side encryption/decryption routines (WebCrypto implementation).
- Cryptographic weaknesses (IV reuse, weak padding/tag verification, salt collisions).
- Authentication bypass or data leakage from the server.
- Remote Code Execution (RCE), Path Traversal, or arbitrary file deletion on the server.
- Failure of the burn-after-reading or disk shredding mechanism.

### Out-of-Scope:
- Attacks requiring physical access or compromised root/admin access to the user's client device.
- Malware, keyloggers, or malicious browser extensions installed on the client machine.
- Social engineering (phishing users to share their `#key` URL fragments).
- Denial of Service (DoS) from volumetric network flooding without software vulnerability.

---

## 📜 Disclosure Policy
We ask that researchers follow responsible disclosure practices:
- Do not access, modify, or delete user data without explicit permission.
- Give the maintainers reasonable time to investigate and remediate the vulnerability before public disclosure.
- Act in good faith to avoid privacy violations, data destruction, and service interruption.
