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
            log("Bowser Key Pair publicKey: " + browserKeyPair.publicKey);

            const clientJwk = await crypto.subtle.exportKey("jwk", browserKeyPair.publicKey);
            clientJwk.key_ops = ["deriveKey", "deriveBits"];
            // 2. Send public key to server
            const response = await fetch("/hybrid-cryptography/client-public", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(clientJwk)
            });

            const serverJwk = await response.json();
            log("Received server public key: " + serverJwk);

            // 3. Import server's public key
            const serverPublicKey = await crypto.subtle.importKey(
                "jwk",
                serverJwk,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            );

            // 4. Derive AES key (256-bit) from shared secret
            const aesKey = await crypto.subtle.deriveKey(
                { name: "ECDH", public: serverPublicKey },
                browserKeyPair.privateKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );

            log("Derived AES-256 key shared with server");

            // 5. Test encryption
            const enc = new TextEncoder();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                aesKey,
                enc.encode("Hello from browser!")
            );

            log("Encrypted test message: " + btoa(String.fromCharCode(...new Uint8Array(ciphertext))));
        });
    </script>
</body>
</html>
