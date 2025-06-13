package com.thirumal.utility;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
/**
 * @author ThirumalM
 * Utility class to generate RSA key pair, convert keys to PEM format 
 * to store it in database as string, and reconstruct keys from PEM format.
 */
public class RsaKeyStorage {

    /**
     * @param args
     * @throws Exception 
     */

    public static void main(String[] args) throws Exception {
        // Step 1: Generate RSA Key Pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Step 2: Export to PEM format
        String privateKeyPem = convertPrivateKeyToPem(privateKey);
        String publicKeyPem = convertPublicKeyToPem(publicKey);

        System.out.println("Generated Public Key PEM:\n" + publicKeyPem);
        System.out.println("\nGenerated Private Key PEM:\n" + privateKeyPem);

        // Simulate storing and retrieving from DB by using these strings

        // Step 3: Reconstruct Public Key from PEM
        PublicKey reconstructedPublicKey = reconstructPublicKeyFromPem(publicKeyPem);

        // Step 4: Reconstruct Private Key from PEM
        PrivateKey reconstructedPrivateKey = reconstructPrivateKeyFromPem(privateKeyPem);

        System.out.println("\nReconstructed Public Key: " + reconstructedPublicKey);
        System.out.println("Reconstructed Private Key: " + reconstructedPrivateKey);
    }
    

    // Convert PrivateKey to PEM string
    public static String convertPrivateKeyToPem(PrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);

        String pem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8EncodedKeySpec.getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        return pem;
    }

    // Convert PublicKey to PEM string
    public static String convertPublicKeyToPem(PublicKey publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec x509EncodedKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);

        String pem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(x509EncodedKeySpec.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        return pem;
    }

    // Reconstruct PublicKey from PEM string
    public static PublicKey reconstructPublicKeyFromPem(String pem) throws Exception {
        String publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                                 .replace("-----END PUBLIC KEY-----", "")
                                 .replaceAll("\\s+", ""); // Remove all whitespace/newlines

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    // Reconstruct PrivateKey from PEM string
    public static PrivateKey reconstructPrivateKeyFromPem(String pem) throws Exception {
        String privateKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                                  .replace("-----END PRIVATE KEY-----", "")
                                  .replaceAll("\\s+", ""); // Remove all whitespace/newlines

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

}
