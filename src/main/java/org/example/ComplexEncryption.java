package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class ComplexEncryption {

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-512";

    private static final SecureRandom secureRandom = new SecureRandom();


    public static String encrypt(String plaintext, String password) throws Exception {
        byte[] salt = generateSalt();

        SecretKey key = generateKey(password, salt);

        byte[] iv = generateIV();

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        cipher.updateAAD(salt);

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);

        byte[] passwordHash = hashPassword(password);
        byte[] xorCiphertext = xorWithPassword(ciphertext, passwordHash);

        ByteBuffer byteBuffer = ByteBuffer.allocate(SALT_LENGTH + IV_LENGTH + xorCiphertext.length);
        byteBuffer.put(salt);
        byteBuffer.put(iv);
        byteBuffer.put(xorCiphertext);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public static String decrypt(String encryptedText, String password) throws Exception {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted text cannot be empty");
        }

        try {
            byte[] encryptedData = Base64.getDecoder().decode(encryptedText);

            if (encryptedData.length < SALT_LENGTH + IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted data: insufficient length");
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            byte[] ciphertextWithTag = new byte[encryptedData.length - SALT_LENGTH - IV_LENGTH];

            byteBuffer.get(salt);
            byteBuffer.get(iv);
            byteBuffer.get(ciphertextWithTag);

            byte[] passwordHash = hashPassword(password);
            byte[] originalCiphertext = xorWithPassword(ciphertextWithTag, passwordHash);

            SecretKey key = generateKey(password, salt);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

            cipher.updateAAD(salt);

            byte[] plaintextBytes = cipher.doFinal(originalCiphertext);

            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 format error: " + e.getMessage());
        }
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private static SecretKey generateKey(String password, byte[] salt) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hashedPassword = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return hashedPassword;
    }

    private static byte[] xorWithPassword(byte[] data, byte[] passwordHash) {
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ passwordHash[i % passwordHash.length]);
        }

        return result;
    }

    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        boolean running = true;

        System.out.println("Complex Encryption");

        while (running) {
            System.out.println("\nSelect action:");
            System.out.println("1. Encrypt message");
            System.out.println("2. Decrypt message");
            System.out.println("3. Exit");
            System.out.print("> ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    encryptInteractive(scanner);
                    break;
                case "2":
                    decryptInteractive(scanner);
                    break;
                case "3":
                    running = false;
                    System.out.println("Program terminated.");
                    break;
                default:
                    System.out.println("Invalid choice. Please select 1, 2, or 3.");
            }
        }

        scanner.close();
    }

    private static void encryptInteractive(java.util.Scanner scanner) {
        try {
            System.out.println("\nMESSAGE ENCRYPTION");

            System.out.print("Enter text to encrypt: ");
            String text = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            if (text.isEmpty() || password.isEmpty()) {
                System.out.println("Error: text and password cannot be empty.");
                return;
            }

            long startTime = System.currentTimeMillis();
            String encryptedText = encrypt(text, password);
            long endTime = System.currentTimeMillis();

            System.out.println("\nEncrypted text:");
            System.out.println(encryptedText);
            System.out.println("\nEncryption time: " + (endTime - startTime) + " ms");
            System.out.println("Save this text and password in a secure place!");

        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private static void decryptInteractive(java.util.Scanner scanner) {
        try {
            System.out.println("\nMESSAGE DECRYPTION");

            System.out.print("Enter encrypted text: ");
            String encryptedText = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            if (encryptedText.isEmpty() || password.isEmpty()) {
                System.out.println("Error: encrypted text and password cannot be empty.");
                return;
            }

            try {
                Base64.getDecoder().decode(encryptedText);
            } catch (IllegalArgumentException e) {
                System.out.println("Error: the entered text is not a valid Base64 string.");
                return;
            }

            long startTime = System.currentTimeMillis();
            String decryptedText = decrypt(encryptedText, password);
            long endTime = System.currentTimeMillis();

            System.out.println("\nDecrypted text:");
            System.out.println(decryptedText);
            System.out.println("\nDecryption time: " + (endTime - startTime) + " ms");

        } catch (Exception e) {
            System.out.println("Decryption error: " + e.getMessage());
            System.out.println("Possibly wrong password or corrupted encrypted text.");
        }
    }
}