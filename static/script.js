const { createApp } = Vue;

createApp({
    data() {
        return {
            selectedAlgorithm: 'aes',
            aesPlaintext: '',
            aesKey: '',
            aesResult: null,
            aesDecrypted: null,
            des3Plaintext: '',
            des3Key: '',
            des3Result: null,
            des3Decrypted: null,
            otpPlaintext: '',
            otpResult: null, // Initialize otpResult as null to avoid template errors
            otpDecrypted: null,
            errorMessage: null
        };
    },
    methods: {
        async encryptAES() {
            this.errorMessage = null; // Clear error message before making API call
            try {
                const response = await fetch('/api/aes/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        plaintext: this.aesPlaintext,
                        key: this.aesKey
                    })
                });
                const data = await response.json(); // Parse JSON response
                if (response.ok) {
                    this.aesResult = data.encrypted_text; // Update AES result
                } else {
                    this.errorMessage = data.error || "AES encryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        },
        async decryptAES() {
            this.errorMessage = null; // Clear error message before making API call
            try {
                const response = await fetch('/api/aes/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ciphertext: this.aesResult,
                        key: this.aesKey
                    })
                });
                const data = await response.json(); // Parse JSON response
                if (response.ok) {
                    this.aesDecrypted = data.decrypted_text; // Update AES decrypted result
                } else {
                    this.errorMessage = data.error || "AES decryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        },
        async encrypt3DES() {
            this.errorMessage = null;
            try {
                const response = await fetch('/api/3des/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        plaintext: this.des3Plaintext,
                        key: this.des3Key
                    })
                });
                const data = await response.json();
                if (response.ok) {
                    this.des3Result = data.encrypted_text; // Update 3DES result
                } else {
                    this.errorMessage = data.error || "3DES encryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        },
        async decrypt3DES() {
            this.errorMessage = null;
            try {
                const response = await fetch('/api/3des/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ciphertext: this.des3Result,
                        key: this.des3Key
                    })
                });
                const data = await response.json();
                if (response.ok) {
                    this.des3Decrypted = data.decrypted_text; // Update 3DES decrypted result
                } else {
                    this.errorMessage = data.error || "3DES decryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        },
        async encryptOTP() {
            this.errorMessage = null;
            try {
                const response = await fetch('/api/otp/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ plaintext: this.otpPlaintext })
                });
                const data = await response.json();
                if (response.ok) {
                    this.otpResult = data; // Update OTP result with both encrypted_text and key
                } else {
                    this.errorMessage = data.error || "OTP encryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        },
        async decryptOTP() {
            this.errorMessage = null;
            try {
                const response = await fetch('/api/otp/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ciphertext: this.otpResult.encrypted_text,
                        key: this.otpResult.key
                    })
                });
                const data = await response.json();
                if (response.ok) {
                    this.otpDecrypted = data.decrypted_text; // Update OTP decrypted result
                } else {
                    this.errorMessage = data.error || "OTP decryption failed.";
                }
            } catch (error) {
                this.errorMessage = "Network error. Please check the server.";
            }
        }
    }
}).mount("#app");