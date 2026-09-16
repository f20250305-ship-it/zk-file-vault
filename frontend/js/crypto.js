/**
 * WebCrypto Engine for Zero-Knowledge File Vault
 * Implements client-side AES-256-GCM and PBKDF2-HMAC-SHA256.
 * Zero external libraries: 100% native browser WebCrypto API.
 */

const VaultCrypto = {
    // Utility: ArrayBuffer to Base64
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    // Utility: Base64 to ArrayBuffer
    base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    // Utility: ArrayBuffer to Hex String
    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Utility: Hex String to ArrayBuffer
    hexToBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes.buffer;
    },

    // Generate a cryptographically secure 256-bit AES-GCM Key
    async generateKey() {
        return await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Export raw key to hex string for URL fragment storage
    async exportKeyToHex(cryptoKey) {
        const raw = await window.crypto.subtle.exportKey("raw", cryptoKey);
        return this.bufferToHex(raw);
    },

    // Import hex string back to AES-GCM CryptoKey
    async importKeyFromHex(hexKey) {
        const rawBuffer = this.hexToBuffer(hexKey);
        return await window.crypto.subtle.importKey(
            "raw",
            rawBuffer,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    },

    // Derive 256-bit AES-GCM key from password using PBKDF2 (100,000 rounds)
    async deriveKeyFromPassword(password, saltBuffer) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBuffer,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    },

    /**
     * Encrypt File Buffer
     * Returns: { ciphertextBase64, ivBase64, saltBase64, encryptedFilenameBase64, keyHex, benchmarkMs }
     */
    async encryptFile(file, password = "") {
        const startTime = performance.now();
        const fileBuffer = await file.arrayBuffer();

        // 96-bit (12-byte) IV standard for AES-GCM
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        let cryptoKey;
        let salt = null;
        let keyHex = "";

        if (password && password.trim().length > 0) {
            // Password-derived mode with 128-bit random salt
            salt = window.crypto.getRandomValues(new Uint8Array(16));
            cryptoKey = await this.deriveKeyFromPassword(password, salt);
        } else {
            // Direct random 256-bit key mode
            cryptoKey = await this.generateKey();
            keyHex = await this.exportKeyToHex(cryptoKey);
        }

        // Encrypt file contents
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            fileBuffer
        );

        // Encrypt filename and MIME type as well so metadata remains zero-knowledge
        const metaObj = { name: file.name, type: file.type || "application/octet-stream" };
        const metaBuffer = new TextEncoder().encode(JSON.stringify(metaObj));
        const encryptedMetaBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            metaBuffer
        );

        const benchmarkMs = Math.round(performance.now() - startTime);

        return {
            ciphertextBase64: this.bufferToBase64(ciphertextBuffer),
            ivBase64: this.bufferToBase64(iv),
            saltBase64: salt ? this.bufferToBase64(salt) : "",
            encryptedFilenameBase64: this.bufferToBase64(encryptedMetaBuffer),
            keyHex: keyHex,
            isPasswordProtected: Boolean(password && password.trim().length > 0),
            benchmarkMs: benchmarkMs,
            originalSize: file.size,
            encryptedSize: ciphertextBuffer.byteLength
        };
    },

    /**
     * Decrypt File Buffer
     * Returns: { blob, filename, mimeType, benchmarkMs }
     */
    async decryptFile(ciphertextBase64, ivBase64, saltBase64, encryptedFilenameBase64, keyHex = "", password = "") {
        const startTime = performance.now();
        const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
        const iv = new Uint8Array(this.base64ToBuffer(ivBase64));

        let cryptoKey;
        if (saltBase64 && password) {
            const saltBuffer = new Uint8Array(this.base64ToBuffer(saltBase64));
            cryptoKey = await this.deriveKeyFromPassword(password, saltBuffer);
        } else if (keyHex) {
            cryptoKey = await this.importKeyFromHex(keyHex);
        } else {
            throw new Error("Missing decryption key or passphrase.");
        }

        // Decrypt ciphertext
        let decryptedFileBuffer;
        try {
            decryptedFileBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                cryptoKey,
                ciphertextBuffer
            );
        } catch (err) {
            throw new Error("Decryption failed. The key/passphrase is incorrect or data was corrupted.");
        }

        // Decrypt metadata (filename + type)
        let filename = "decrypted_file";
        let mimeType = "application/octet-stream";

        if (encryptedFilenameBase64) {
            try {
                const metaCipherBuffer = this.base64ToBuffer(encryptedFilenameBase64);
                const decryptedMetaBuffer = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    cryptoKey,
                    metaCipherBuffer
                );
                const metaStr = new TextDecoder().decode(decryptedMetaBuffer);
                const meta = JSON.parse(metaStr);
                filename = meta.name || filename;
                mimeType = meta.type || mimeType;
            } catch (e) {
                console.warn("Could not decrypt filename metadata:", e);
            }
        }

        const blob = new Blob([decryptedFileBuffer], { type: mimeType });
        const benchmarkMs = Math.round(performance.now() - startTime);

        return {
            blob: blob,
            filename: filename,
            mimeType: mimeType,
            size: decryptedFileBuffer.byteLength,
            benchmarkMs: benchmarkMs
        };
    }
};
