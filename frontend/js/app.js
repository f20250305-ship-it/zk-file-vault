/**
 * Zero-Knowledge Vault Frontend Controller
 */

document.addEventListener("DOMContentLoaded", () => {
    // State
    let selectedFile = null;

    // Elements - Tabs
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    // Elements - Upload
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const filePill = document.getElementById("filePill");
    const fileNameSpan = document.getElementById("fileName");
    const fileSizeSpan = document.getElementById("fileSize");
    const clearFileBtn = document.getElementById("clearFileBtn");
    const passwordInput = document.getElementById("passwordInput");
    const expirationSelect = document.getElementById("expirationSelect");
    const maxDownloadsSelect = document.getElementById("maxDownloadsSelect");
    const burnNotice = document.getElementById("burnNotice");
    const encryptUploadBtn = document.getElementById("encryptUploadBtn");
    const uploadTelemetry = document.getElementById("uploadTelemetry");
    const uploadResult = document.getElementById("uploadResult");
    const shareLinkInput = document.getElementById("shareLinkInput");
    const copyLinkBtn = document.getElementById("copyLinkBtn");

    // Elements - Decrypt
    const decryptLinkInput = document.getElementById("decryptLinkInput");
    const decryptPasswordInput = document.getElementById("decryptPasswordInput");
    const decryptBtn = document.getElementById("decryptBtn");
    const decryptStatus = document.getElementById("decryptStatus");
    const decryptTelemetry = document.getElementById("decryptTelemetry");

    // Elements - Status
    const vaultStatusText = document.getElementById("vaultStatusText");

    // ----------------------------------------------------
    // Tab Navigation
    // ----------------------------------------------------
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.getAttribute("data-tab");
            tabBtns.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            const targetContent = document.getElementById(target);
            if (targetContent) targetContent.classList.add("active");
        });
    });

    // ----------------------------------------------------
    // Drag & Drop File Handling
    // ----------------------------------------------------
    dropZone.addEventListener("click", () => fileInput.click());

    ["dragenter", "dragover"].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", (e) => {
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function formatBytes(bytes) {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function handleFileSelect(file) {
        if (file.size > 50 * 1024 * 1024) {
            alert("File exceeds maximum allowed size of 50MB.");
            return;
        }
        selectedFile = file;
        fileNameSpan.textContent = file.name;
        fileSizeSpan.textContent = `(${formatBytes(file.size)})`;
        filePill.style.display = "inline-flex";
        encryptUploadBtn.disabled = false;
    }

    clearFileBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        selectedFile = null;
        fileInput.value = "";
        filePill.style.display = "none";
        encryptUploadBtn.disabled = true;
        uploadTelemetry.style.display = "none";
        uploadResult.classList.remove("active");
    });

    maxDownloadsSelect.addEventListener("change", () => {
        if (maxDownloadsSelect.value === "1") {
            burnNotice.style.display = "flex";
        } else {
            burnNotice.style.display = "none";
        }
    });

    // ----------------------------------------------------
    // Encrypt & Upload Action
    // ----------------------------------------------------
    encryptUploadBtn.addEventListener("click", async () => {
        if (!selectedFile) return;

        try {
            encryptUploadBtn.disabled = true;
            encryptUploadBtn.innerHTML = `<span>🔒 Encrypting in browser with AES-256-GCM...</span>`;

            // 1. Client-Side Encryption via WebCrypto
            const password = passwordInput.value.trim();
            const encrypted = await VaultCrypto.encryptFile(selectedFile, password);

            // Display Cryptographic Telemetry
            document.getElementById("telemetryIv").textContent = encrypted.ivBase64.substring(0, 16) + "... (96-bit)";
            document.getElementById("telemetrySalt").textContent = encrypted.saltBase64 ? (encrypted.saltBase64.substring(0, 16) + "... (128-bit)") : "N/A (Direct Key Mode)";
            document.getElementById("telemetryCiphertextSize").textContent = formatBytes(encrypted.encryptedSize);
            document.getElementById("telemetryTime").textContent = `${encrypted.benchmarkMs} ms`;
            uploadTelemetry.style.display = "block";

            encryptUploadBtn.innerHTML = `<span>📡 Transmitting blinded ciphertext to vault...</span>`;

            // 2. Transmit Ciphertext to Server
            const payload = {
                ciphertext: encrypted.ciphertextBase64,
                iv: encrypted.ivBase64,
                salt: encrypted.saltBase64,
                encrypted_filename: encrypted.encryptedFilenameBase64,
                expires_in: parseInt(expirationSelect.value),
                max_downloads: parseInt(maxDownloadsSelect.value)
            };

            const response = await VaultAPI.uploadPayload(payload);

            // 3. Construct Zero-Knowledge Share URL
            // The encryption key is anchored in the URL fragment #, ensuring it is NEVER sent in HTTP headers!
            let shareUrl = `${window.location.origin}/d/${response.file_id}`;
            if (encrypted.keyHex) {
                shareUrl += `#key=${encrypted.keyHex}`;
            }

            shareLinkInput.value = shareUrl;
            uploadResult.classList.add("active");
            encryptUploadBtn.innerHTML = `<span>✔ Encryption & Secure Storage Complete</span>`;

            // Trigger telemetry refresh
            updateVaultStats();

        } catch (err) {
            console.error("Encryption error:", err);
            alert("Error during encryption/upload: " + err.message);
            encryptUploadBtn.disabled = false;
            encryptUploadBtn.innerHTML = `<span>🔒 Encrypt & Store in Vault</span>`;
        }
    });

    copyLinkBtn.addEventListener("click", () => {
        shareLinkInput.select();
        navigator.clipboard.writeText(shareLinkInput.value);
        const originalText = copyLinkBtn.textContent;
        copyLinkBtn.textContent = "Copied! ✔";
        setTimeout(() => copyLinkBtn.textContent = originalText, 2000);
    });

    // ----------------------------------------------------
    // Decrypt & Download Action
    // ----------------------------------------------------
    decryptBtn.addEventListener("click", async () => {
        const inputUrl = decryptLinkInput.value.trim();
        if (!inputUrl) {
            alert("Please paste a valid Vault Share Link.");
            return;
        }

        try {
            decryptBtn.disabled = true;
            decryptBtn.textContent = "Fetching blinded ciphertext...";
            decryptStatus.innerHTML = `<span style="color: var(--text-cyan);">📡 Contacting vault server...</span>`;

            // Parse File ID and Key from URL
            const urlObj = new URL(inputUrl, window.location.origin);
            const pathParts = urlObj.pathname.split("/").filter(Boolean);
            const fileId = pathParts[pathParts.length - 1];

            // Extract #key=... from hash fragment
            let keyHex = "";
            if (urlObj.hash && urlObj.hash.includes("key=")) {
                const match = urlObj.hash.match(/key=([0-9a-fA-F]+)/);
                if (match) keyHex = match[1];
            }

            const password = decryptPasswordInput.value.trim();

            // 1. Download encrypted payload from server
            const payload = await VaultAPI.downloadFilePayload(fileId);

            decryptBtn.textContent = "Decrypting locally in browser memory...";
            decryptStatus.innerHTML = `<span style="color: var(--text-emerald);">🔑 Running WebCrypto AES-256-GCM decryption...</span>`;

            // 2. Decrypt in-memory
            const decrypted = await VaultCrypto.decryptFile(
                payload.ciphertext,
                payload.iv,
                payload.salt,
                payload.encrypted_filename,
                keyHex,
                password
            );

            // Display Decryption Telemetry
            document.getElementById("decryptTelemetryFilename").textContent = decrypted.filename;
            document.getElementById("decryptTelemetrySize").textContent = formatBytes(decrypted.size);
            document.getElementById("decryptTelemetryTime").textContent = `${decrypted.benchmarkMs} ms`;
            document.getElementById("decryptTelemetryBurned").textContent = payload.burned ? "YES (Permanently Shredded from Server)" : `${payload.remaining_downloads} downloads left`;
            decryptTelemetry.style.display = "block";

            // 3. Trigger Download of Plaintext File
            const downloadUrl = URL.createObjectURL(decrypted.blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = decrypted.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(downloadUrl);

            decryptStatus.innerHTML = `<span style="color: var(--text-emerald); font-weight: bold;">✔ Decrypted & Downloaded Successfully!</span>`;
            decryptBtn.disabled = false;
            decryptBtn.textContent = "🔓 Decrypt & Download File";

            // Update stats
            updateVaultStats();

        } catch (err) {
            console.error("Decryption failed:", err);
            decryptStatus.innerHTML = `<span style="color: var(--text-crimson); font-weight: bold;">❌ ${err.message}</span>`;
            decryptBtn.disabled = false;
            decryptBtn.textContent = "🔓 Decrypt & Download File";
        }
    });

    // ----------------------------------------------------
    // Auto-detect Link from URL
    // ----------------------------------------------------
    function checkIncomingShareLink() {
        const path = window.location.pathname;
        if (path.startsWith("/d/") || path.startsWith("/decrypt/")) {
            // User opened a direct download link!
            const fullUrl = window.location.href;
            decryptLinkInput.value = fullUrl;

            // Switch to Decrypt tab
            const decryptTabBtn = document.querySelector('[data-tab="decryptTab"]');
            if (decryptTabBtn) decryptTabBtn.click();

            // If key is present in hash, show prompt
            if (window.location.hash.includes("key=")) {
                decryptStatus.innerHTML = `<span style="color: var(--text-cyan);">Zero-knowledge key detected in URL fragment! Click 'Decrypt & Download' below.</span>`;
            }
        }
    }

    // ----------------------------------------------------
    // Vault Stats Telemetry
    // ----------------------------------------------------
    async function updateVaultStats() {
        const stats = await VaultAPI.getStats();
        if (stats && vaultStatusText) {
            vaultStatusText.textContent = `${stats.active_vault_files} Active Vault Blobs | Zero-Knowledge Active`;
        }
    }

    checkIncomingShareLink();
    updateVaultStats();
    setInterval(updateVaultStats, 15000);
});
