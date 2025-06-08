<!DOCTYPE html>
<html>
<head>
    <title>ECDH Handshake Demo</title>
</head>
<body>
    <h1>ECDH Handshake</h1>
    <button id="start">Start Handshake</button>
    <pre id="log"></pre>

    <script>
        const log = msg => document.getElementById("log").textContent += msg + "\n";

        document.getElementById("start").addEventListener("click", async () => {
            log("Generating ECDH key pair...");

            // 1. Generate browser key pair (P-256)
            const browserKeyPair = await crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                true,
                ["deriveKey", "deriveBits"]
            );

            const privateJwk = await crypto.subtle.exportKey("jwk", browserKeyPair.privateKey);
            log("Private Key (JWK): " + JSON.stringify(privateJwk, null, 2));

            const publicJwk = await crypto.subtle.exportKey("jwk", browserKeyPair.publicKey);
            log("Public Key (JWK): " + JSON.stringify(publicJwk, null, 2));

            // 2. Send public key to server
            const response = await fetch("/hybrid-cryptography/client-public", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(publicJwk)
            });

            const serverJwk = await response.json();
            log("Received server public key: " + JSON.stringify(serverJwk, null, 2));

            // 3. Import server's public key
            const serverPublicKey = await crypto.subtle.importKey(
                "jwk",
                serverJwk,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            );

            // 4. Derive AES key (256-bit) using SHA-256 hash of ECDH shared secret
            const sharedSecretBits = await crypto.subtle.deriveBits(
                { name: "ECDH", public: serverPublicKey },
                browserKeyPair.privateKey,
                256
            );

            const hashedSecret = await crypto.subtle.digest("SHA-256", sharedSecretBits);

            const aesKey = await crypto.subtle.importKey(
                "raw",
                hashedSecret,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            log("Derived AES-256 key (from shared secret + SHA-256)");

            // ✅ Log Base64 of raw AES key
            const rawKey = await crypto.subtle.exportKey("raw", aesKey);
            const base64Key = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
            log("Derived AES Key (Base64): " + base64Key);

            // 5. Encrypt a test message
            const enc = new TextEncoder();
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM

            const ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                aesKey,
                enc.encode("Hello from browser!")
            );

            const payload = {
                ciphertext: Array.from(new Uint8Array(ciphertext)),
                iv: Array.from(iv)
            };

            log("IV (Base64): " + btoa(String.fromCharCode(...iv)));
            log("Ciphertext (Base64): " + btoa(String.fromCharCode(...new Uint8Array(ciphertext))));

            // 6. Send ciphertext to server for decryption
            const encResponse = await fetch("/hybrid-cryptography/decrypt-message", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const plainText = await encResponse.text();
            log("Server decrypted message: " + plainText);
        });
    </script>
</body>
</html>
