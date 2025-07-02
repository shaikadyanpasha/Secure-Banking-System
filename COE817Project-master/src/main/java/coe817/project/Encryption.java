package coe817.project;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// part 3
import java.security.MessageDigest;

// part4
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// replay protection
import java.util.UUID;

public class Encryption {

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /*public static String generateNonce() {
        SecureRandom random = new SecureRandom();
        return String.valueOf(random.nextInt(100000));
    }*/

    public static String encryptRSA(String data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int maxLength = 245; // For 2048 bit RSA
        byte[] bytes = data.getBytes();
        List<byte[]> blocks = new ArrayList<>();

        // Split data into blocks
        for (int i = 0; i < bytes.length; i += maxLength) {
            int blockSize = Math.min(maxLength, bytes.length - i);
            byte[] block = new byte[blockSize];
            System.arraycopy(bytes, i, block, 0, blockSize);
            blocks.add(block);
        }

        // Encrypt each block
        List<byte[]> encryptedBlocks = new ArrayList<>();
        for (byte[] block : blocks) {
            byte[] encryptedBlock = cipher.doFinal(block);
            encryptedBlocks.add(encryptedBlock);
        }

        // Combine encrypted blocks
        int totalLength = encryptedBlocks.stream().mapToInt(b -> b.length).sum();
        byte[] encryptedData = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] block : encryptedBlocks) {
            System.arraycopy(block, 0, encryptedData, currentIndex, block.length);
            currentIndex += block.length;
        }

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decryptRSA(String encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        int blockSize = 256; // For 2048 bit RSA
        List<byte[]> blocks = new ArrayList<>();

        // Split encrypted data into blocks
        for (int i = 0; i < encryptedBytes.length; i += blockSize) {
            int currentBlockSize = Math.min(blockSize, encryptedBytes.length - i);
            byte[] block = new byte[currentBlockSize];
            System.arraycopy(encryptedBytes, i, block, 0, currentBlockSize);
            blocks.add(block);
        }

        // Decrypt each block
        StringBuilder decryptedText = new StringBuilder();
        for (byte[] block : blocks) {
            byte[] decryptedBlock = cipher.doFinal(block);
            decryptedText.append(new String(decryptedBlock));
        }

        return decryptedText.toString();
    }

    public static PublicKey getPublicKeyFromString(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static SecretKey generateSecretKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(new SecureRandom());
        return keyGenerator.generateKey();
    }

    // Method to generate a session key (KAB) between two parties (A and B)
    public static SecretKey generateSessionKey() throws NoSuchAlgorithmException {
        return generateSecretKey("AES");
    }

    public static String encodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String AESencrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    public static String AESdecrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }
    public static SecretKey convertToAESKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);  // Decode the Base64 string
        return new SecretKeySpec(decodedKey, "AES");  // Create a SecretKey from the byte array
    }

    // Derives a purpose-specific AES key from the Master Secret using SHA-256 (part 3)
    public static SecretKey deriveKey(SecretKey masterKey, String purpose) throws Exception {
        // Get raw bytes from Master Secret and purpose string
        byte[] keyBytes = masterKey.getEncoded();
        byte[] purposeBytes = purpose.getBytes();

        // Combine key and purpose bytes into one array
        byte[] combined = new byte[keyBytes.length + purposeBytes.length];
        System.arraycopy(keyBytes, 0, combined, 0, keyBytes.length);
        System.arraycopy(purposeBytes, 0, combined, keyBytes.length, purposeBytes.length);

        // Hash the combined data using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(combined);

        // Use the first 16 bytes (128 bits) of the hash as AES key material
        byte[] aesKeyBytes = new byte[16];
        System.arraycopy(hash, 0, aesKeyBytes, 0, 16);

        // Return derived AES key
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // Generate a MAC using HMAC-SHA256 (part 4)
    public static String generateMAC(String data, SecretKey macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        byte[] macBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(macBytes);
    }

    // Verify MAC by regenerating and comparing
    public static boolean verifyMAC(String data, String receivedMAC, SecretKey macKey) throws Exception {
        String expectedMAC = generateMAC(data, macKey);
        return expectedMAC.equals(receivedMAC);
    }

    //Nonce - replay protection
    public static String generateNonce() {
    return UUID.randomUUID().toString();
    }   

}

