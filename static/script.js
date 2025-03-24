document.addEventListener("DOMContentLoaded", () => {
    const algorithmSelect = document.getElementById("algorithm");
    const plaintextInput = document.getElementById("plaintext");
    const encryptedTextInput = document.getElementById("encryptedText");
    const keyInput = document.getElementById("key");
    const encryptedResultTextarea = document.getElementById("encryptedResult");
    const decryptedResultTextarea = document.getElementById("decryptedResult");
    const errorDiv = document.getElementById("error");

    function showError(message) {
        errorDiv.textContent = message;
        errorDiv.style.display = "block";
    }

    function clearError() {
        errorDiv.textContent = "";
        errorDiv.style.display = "none";
    }

    async function encrypt() {
        clearError();
        const algorithm = algorithmSelect.value;
        const plaintext = plaintextInput.value.trim();
        const key = keyInput.value.trim();

        if (!plaintext) {
            showError("Plaintext is required.");
            return;
        }
        if (!key) {
            showError("Key is required.");
            return;
        }

        try {
            const response = await fetch(`/api/${algorithm}/encrypt`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ plaintext, key }),
            });
            const data = await response.json();
            if (response.ok) {
                encryptedResultTextarea.value = data.encrypted_text;
                encryptedTextInput.value = data.encrypted_text; // Automatically fill the encrypted text for decryption
            } else {
                showError(data.error || "Encryption failed.");
            }
        } catch (error) {
            showError("Network error. Check Flask server.");
        }
    }

    async function decrypt() {
        clearError();
        const algorithm = algorithmSelect.value;
        const encrypted = encryptedTextInput.value.trim();
        const key = keyInput.value.trim();

        if (!encrypted) {
            showError("Encrypted text is required.");
            return;
        }
        if (!key) {
            showError("Key is required.");
            return;
        }

        try {
            const response = await fetch(`/api/${algorithm}/decrypt`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ encrypted, key }),
            });
            const data = await response.json();
            if (response.ok) {
                decryptedResultTextarea.value = data.decrypted_text;
            } else {
                showError(data.error || "Decryption failed.");
            }
        } catch (error) {
            showError("Network error. Check Flask server.");
        }
    }

    function copyToClipboard(elementId) {
        const text = document.getElementById(elementId).value;
        if (!text) {
            alert("Nothing to copy!");
            return;
        }
        navigator.clipboard.writeText(text).then(
            () => alert("Copied to clipboard!"),
            () => alert("Failed to copy!")
        );
    }

    function clearAll() {
        plaintextInput.value = "";
        encryptedTextInput.value = "";
        keyInput.value = "";
        encryptedResultTextarea.value = "";
        decryptedResultTextarea.value = "";
        clearError();
    }

    document.getElementById("encryptButton").addEventListener("click", encrypt);
    document.getElementById("decryptButton").addEventListener("click", decrypt);
    document.getElementById("copyPlaintextButton").addEventListener("click", () => copyToClipboard("plaintext"));
    document.getElementById("copyEncryptedTextButton").addEventListener("click", () => copyToClipboard("encryptedText"));
    document.getElementById("clearButton").addEventListener("click", clearAll);
});