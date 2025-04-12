package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class AlternativeEncryption {
    private static final String ECC_ALGORITHM = "EC";
    private static final String ECC_CURVE = "secp256r1";
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private static final String CHACHA_ALGORITHM = "ChaCha20-Poly1305";
    private static final int NONCE_LENGTH = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String[] args) {
        runInteractive();
    }

    public static void runInteractive() {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        System.out.println("ChaCha20-Poly1305 with ECC Encryption");
        System.out.println("(A less common but highly secure encryption approach)");

        while (running) {
            System.out.println("\nSelect action:");
            System.out.println("1. Generate new key pair");
            System.out.println("2. Encrypt message (using recipient's public key)");
            System.out.println("3. Decrypt message (using your private key)");
            System.out.println("4. Exit");
            System.out.print("> ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    generateKeyPairInteractive();
                    break;
                case "2":
                    encryptInteractive(scanner);
                    break;
                case "3":
                    decryptInteractive(scanner);
                    break;
                case "4":
                    running = false;
                    System.out.println("Program terminated.");
                    break;
                default:
                    System.out.println("Invalid choice. Please select a valid option.");
            }
        }

        scanner.close();
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECC_ALGORITHM);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(ECC_CURVE);
        keyPairGenerator.initialize(ecSpec, SECURE_RANDOM);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String encodePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static PublicKey decodePublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ECC_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey decodePrivateKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ECC_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static String encrypt(String message, PrivateKey senderPrivateKey, PublicKey recipientPublicKey) throws Exception {
        byte[] sharedSecret = deriveSharedSecret(senderPrivateKey, recipientPublicKey);

        byte[] encryptionKey = hashSharedSecret(sharedSecret);

        byte[] nonce = new byte[NONCE_LENGTH];
        SECURE_RANDOM.nextBytes(nonce);

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encryptWithChaCha20Poly1305(messageBytes, encryptionKey, nonce);

        byte[] combined = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(senderPrivateKey);
        signature.update(combined);
        byte[] signatureBytes = signature.sign();

        ByteBuffer buffer = ByteBuffer.allocate(4 + signatureBytes.length + combined.length);
        buffer.putInt(signatureBytes.length);
        buffer.put(signatureBytes);
        buffer.put(combined);

        return Base64.getEncoder().encodeToString(buffer.array());
    }

    private static byte[] encryptWithChaCha20Poly1305(byte[] data, byte[] key, byte[] nonce) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20-Poly1305");
        Cipher cipher = Cipher.getInstance(CHACHA_ALGORITHM);
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        return cipher.doFinal(data);
    }

    private static byte[] hashSharedSecret(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sharedSecret);
    }

    public static String decrypt(String encryptedMessage, PrivateKey recipientPrivateKey) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedMessage);
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);

        int signatureLength = buffer.getInt();
        byte[] signatureBytes = new byte[signatureLength];
        buffer.get(signatureBytes);

        byte[] remaining = new byte[buffer.remaining()];
        buffer.get(remaining);

        byte[] nonce = Arrays.copyOfRange(remaining, 0, NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(remaining, NONCE_LENGTH, remaining.length);

        System.out.println("btw in a production system, you would need to know the sender's public key.");
        System.out.print("Enter sender's public key: ");
        Scanner scanner = new Scanner(System.in);
        String senderPublicKeyStr = scanner.nextLine();
        PublicKey senderPublicKey = decodePublicKey(senderPublicKeyStr);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(senderPublicKey);
        signature.update(remaining);
        boolean verified = signature.verify(signatureBytes);

        if (!verified) {
            throw new SecurityException("Message signature verification failed");
        }

        byte[] sharedSecret = deriveSharedSecret(recipientPrivateKey, senderPublicKey);

        byte[] decryptionKey = hashSharedSecret(sharedSecret);

        byte[] decryptedBytes = decryptWithChaCha20Poly1305(ciphertext, decryptionKey, nonce);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] decryptWithChaCha20Poly1305(byte[] ciphertext, byte[] key, byte[] nonce) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20-Poly1305");
        Cipher cipher = Cipher.getInstance(CHACHA_ALGORITHM);
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        return cipher.doFinal(ciphertext);
    }

    private static void generateKeyPairInteractive() {
        try {
            System.out.println("\nGenerating ECC Key Pair");
            KeyPair keyPair = generateKeyPair();

            String publicKeyString = encodePublicKey(keyPair.getPublic());
            String privateKeyString = encodePrivateKey(keyPair.getPrivate());

            System.out.println("\nYour Public Key (share this with others):");
            System.out.println(publicKeyString);

            System.out.println("\nYour Private Key (keep this secret!):");
            System.out.println(privateKeyString);

            System.out.println("\nSave both keys securely. You'll need them for encryption and decryption.");

        } catch (Exception e) {
            System.out.println("Error generating key pair: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptInteractive(Scanner scanner) {
        try {
            System.out.println("\nEncrypting Message");

            System.out.print("Enter your private key: ");
            String senderPrivateKeyString = scanner.nextLine();

            System.out.print("Enter recipient's public key: ");
            String recipientPublicKeyString = scanner.nextLine();

            System.out.print("Enter message to encrypt: ");
            String message = scanner.nextLine();

            if (senderPrivateKeyString.isEmpty() || recipientPublicKeyString.isEmpty() || message.isEmpty()) {
                System.out.println("Error: All fields are required.");
                return;
            }

            PrivateKey senderPrivateKey = decodePrivateKey(senderPrivateKeyString);
            PublicKey recipientPublicKey = decodePublicKey(recipientPublicKeyString);

            long startTime = System.currentTimeMillis();
            String encryptedMessage = encrypt(message, senderPrivateKey, recipientPublicKey);
            long endTime = System.currentTimeMillis();

            System.out.println("\nEncrypted message:");
            System.out.println(encryptedMessage);
            System.out.println("\nEncryption time: " + (endTime - startTime) + " ms");

        } catch (Exception e) {
            System.out.println("Error encrypting message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void decryptInteractive(Scanner scanner) {
        try {
            System.out.println("\nDecrypting Message");

            System.out.print("Enter your private key: ");
            String privateKeyString = scanner.nextLine();

            System.out.print("Enter encrypted message: ");
            String encryptedMessage = scanner.nextLine();

            if (privateKeyString.isEmpty() || encryptedMessage.isEmpty()) {
                System.out.println("Error: All fields are required.");
                return;
            }

            PrivateKey privateKey = decodePrivateKey(privateKeyString);

            long startTime = System.currentTimeMillis();
            String decryptedMessage = decrypt(encryptedMessage, privateKey);
            long endTime = System.currentTimeMillis();

            System.out.println("\nDecrypted message:");
            System.out.println(decryptedMessage);
            System.out.println("\nDecryption time: " + (endTime - startTime) + " ms");

        } catch (Exception e) {
            System.out.println("Error decrypting message: " + e.getMessage());
            e.printStackTrace();
        }
    }
}