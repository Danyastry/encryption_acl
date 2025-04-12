package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class StandardEncryption {

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATION_COUNT = 65536;

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

    private static final SecureRandom secureRandom = new SecureRandom();


    public static void main(String[] args) {
        runInteractive();
    }

    public static void runInteractive() {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        boolean running = true;

        System.out.println("AES-256 GCM Encryption");

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

    public static String encrypt(String plaintext, String password) throws Exception {
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        SecretKey key = deriveKey(password, salt);

        byte[] iv = generateRandomBytes(IV_LENGTH);

        byte[] ciphertext = performEncryption(plaintext.getBytes(StandardCharsets.UTF_8), key, iv, salt);

        byte[] combined = combineByteArrays(salt, iv, ciphertext);

        return Base64.getEncoder().encodeToString(combined);
    }


    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }


    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] performEncryption(byte[] data, SecretKey key, byte[] iv, byte[] associatedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }

        return cipher.doFinal(data);
    }

    private static byte[] combineByteArrays(byte[] salt, byte[] iv, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(salt.length + iv.length + ciphertext.length);
        buffer.put(salt);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }


    public static String decrypt(String encryptedText, String password) throws Exception {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted text cannot be empty");
        }

        try {
            byte[] encryptedData = Base64.getDecoder().decode(encryptedText);

            if (encryptedData.length < SALT_LENGTH + IV_LENGTH + 16) {
                throw new IllegalArgumentException("Invalid encrypted data: insufficient length");
            }

            ByteArrayComponents components = extractComponents(encryptedData);

            SecretKey key = deriveKey(password, components.salt);

            byte[] decryptedData = performDecryption(components.ciphertext, key, components.iv, components.salt);

            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 format error: " + e.getMessage());
        }
    }

    private static ByteArrayComponents extractComponents(byte[] encryptedData) {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[encryptedData.length - SALT_LENGTH - IV_LENGTH];

        buffer.get(salt);
        buffer.get(iv);
        buffer.get(ciphertext);

        return new ByteArrayComponents(salt, iv, ciphertext);
    }

    private static class ByteArrayComponents {
        final byte[] salt;
        final byte[] iv;
        final byte[] ciphertext;

        ByteArrayComponents(byte[] salt, byte[] iv, byte[] ciphertext) {
            this.salt = salt;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    private static byte[] performDecryption(byte[] data, SecretKey key, byte[] iv, byte[] associatedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }

        return cipher.doFinal(data);
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