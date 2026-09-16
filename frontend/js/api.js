/**
 * Vault REST API Client
 */

const VaultAPI = {
    async uploadPayload(data) {
        const resp = await fetch("/api/vault/upload", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || `Upload failed with status ${resp.status}`);
        }
        return result;
    },

    async getFileMetadata(fileId) {
        const resp = await fetch(`/api/vault/meta/${fileId}`);
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || `Could not fetch metadata for file ${fileId}`);
        }
        return result.metadata;
    },

    async downloadFilePayload(fileId) {
        const resp = await fetch(`/api/vault/file/${fileId}`);
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || `Download failed for file ${fileId}`);
        }
        return result.payload;
    },

    async getStats() {
        try {
            const resp = await fetch("/api/vault/stats");
            return await resp.json();
        } catch (e) {
            return null;
        }
    }
};
