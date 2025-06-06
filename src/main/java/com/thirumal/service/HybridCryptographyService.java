package com.thirumal.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.thirumal.model.EncryptedMessage;
import com.thirumal.model.JwkRequest;

@Service
public class HybridCryptographyService {

    Logger logger = LoggerFactory.getLogger(HybridCryptographyService.class.getName());

    private static final String CURVE_NAME = "secp256r1"; // P-256
    private KeyPair serverKeyPair;
    private PublicKey clientPublicKey;
    private static final Base64.Decoder urlDecoder = Base64.getUrlDecoder();
    private static final Base64.Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();

    HashMap<String, SecretKey> sharedSecrets = new HashMap<>();

    public String initiateHandShake() {
        logger.info("Generating ECDH key pair");
        // Generate ECDH key pair
        // Generate AES key
        logger.info("Generating AES key");
        // Encrypt AES key with ECDH public key
        logger.info("Encrypting AES key with ECDH public key");
        // Send ECDH public key and encrypted AES key to the client
        logger.info("Sending ECDH public key and encrypted AES key to the client");
        // Return a success message or redirect to a success page
        return "Handshake initiated successfully. ECDH public key and encrypted AES key sent to the client.";
    }

    public PublicKey convertJwkToPublicKey(JwkRequest jwkRequest) throws Exception {
        logger.info("Converting JWK to Public Key");
        byte[] xBytes = Base64.getUrlDecoder().decode(jwkRequest.getX());
        byte[] yBytes = Base64.getUrlDecoder().decode(jwkRequest.getY());

        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);
        ECPoint ecPoint = new ECPoint(x, y);

        // Use P-256 curve
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        var kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1")); // aka P-256
        var params = ((java.security.interfaces.ECPrivateKey) kpg.generateKeyPair().getPrivate()).getParams();

        var pubKeySpec = new ECPublicKeySpec(ecPoint, params);
        return keyFactory.generatePublic(pubKeySpec);
    }


    public JwkRequest exportPublicKeyToJwk(PublicKey publicKey) {
        logger.info("Exporting Public Key to JWK format");
        ECPublicKey ecPub = (ECPublicKey) publicKey;
        BigInteger x = ecPub.getW().getAffineX();
        BigInteger y = ecPub.getW().getAffineY();
        return JwkRequest.builder()
                .kty("EC")
                .crv("P-256")
                .x(urlEncoder.encodeToString(toUnsignedBytes(x)))
                .y(urlEncoder.encodeToString(toUnsignedBytes(y)))
                .build();
    }

    public KeyPair generateEcKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        logger.info("Generating ECDH key pair with curve: " + CURVE_NAME);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        AlgorithmParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public SecretKey deriveAesKey(PrivateKey privateKey, PublicKey clientPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(clientPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();

        // Derive AES-256 key using SHA-256 hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKeyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(aesKeyBytes, 0, 32, "AES");
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] full = value.toByteArray();
        if (full[0] == 0) {
            return Arrays.copyOfRange(full, 1, full.length);
        }
        return full;
    }

    public JwkRequest receiveClientKey( String jsessionId, JwkRequest jwkeRequest) throws Exception {
        clientPublicKey = convertJwkToPublicKey(jwkeRequest);

        serverKeyPair = generateEcKeyPair();
        SecretKey sharedSecret = deriveAesKey(serverKeyPair.getPrivate(), clientPublicKey);
        logger.info("Shared secret derived successfully {}", sharedSecret);
        // You can store sharedSecret in session or memory
        sharedSecrets.put(jsessionId, sharedSecret);
        return exportPublicKeyToJwk(serverKeyPair.getPublic());
    }

    public String decryptMessage(String jsessionId, EncryptedMessage encryptedMessage) {
        byte[] iv = toByteArray(encryptedMessage.getIv());
        byte[] cipherBytes = toByteArray(encryptedMessage.getCiphertext());
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            SecretKey sharedSecretKey = sharedSecrets.get(jsessionId);
            cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey, spec);
            decrypted = cipher.doFinal(cipherBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private byte[] toByteArray(List<Integer> list) {
        byte[] arr = new byte[list.size()];
        for (int i = 0; i < list.size(); i++) {
            arr[i] = list.get(i).byteValue();
        }
        return arr;
    }
}
