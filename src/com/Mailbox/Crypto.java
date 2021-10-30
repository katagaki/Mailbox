package com.Mailbox;

import com.Mailbox.Logging;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    
    // MARK: SHA1 hash functions
    
    public static String getSHA1(String originalText) {
        try {
            
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(originalText.getBytes("UTF-8"));
            
            Logging.printLog("CRX", "Generating SHA-1 digest...");
            
            return String.format("%040x", new BigInteger(1, digest.digest()));
            
        } catch (Exception e) {
            Logging.printError("Failed to obtain a SHA-1 hash.");
            return "";
        }
    }
    
    // MARK: Diffie-Hellman functions
    
    public static BigInteger getPrime(int bits) {
        
        try {
            
            BigInteger bILower, bIUpper, bIDifference, bIPrime;
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
            
            Logging.printLog("CRX", "Generating prime number...");
            
            do {
                bIPrime = new BigInteger(bits, 1, rng);
            } while (!bIPrime.isProbablePrime(100));
            
            return bIPrime;
            
        } catch (Exception e) {
            Logging.printError("Failed to obtain a reliable prime number, will default to 0.");
            return BigInteger.ZERO;
        }
        
    }
    
    public static BigInteger getPublicKey(BigInteger privateKey, BigInteger generator, BigInteger sharedPrime) {
        
        Logging.printLog("CRX", "Calculating public key...");
        
        return generator.modPow(privateKey, sharedPrime);
    }
    
    public static BigInteger getSharedSecret(BigInteger publicKey, BigInteger privateKey, BigInteger sharedPrime) {
        
        Logging.printLog("CRX", "Calculating shared secret...");
        
        return publicKey.modPow(privateKey, sharedPrime);
    }
    
    public static long getNonce() {
        return (System.currentTimeMillis() / 1000);
    }
    
    // MARK: AES encryption functions
    // Modified from https://howtodoinjava.com/java/java-security/java-aes-encryption-example/
    
    public static String encrypt(String message, String secret) {
        try {
            
            Logging.printLog("CRX", "Encrypting message of length " + message.length() + " with a secret of length " + secret.length() + ".");
            
            byte[] secretByteArray = MessageDigest.getInstance("SHA-1").digest(secret.getBytes("UTF-8"));
            secretByteArray = Arrays.copyOf(secretByteArray, 16);
            SecretKeySpec secretKey = new SecretKeySpec(secretByteArray, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
            
        } catch (Exception e) {
            Logging.printError("Failed to encrypt a message.");
            return null;
        }
    }
    
    public static String encrypt(String message, BigInteger secret) {
        return encrypt(message, String.valueOf(secret));
    }
    
    public static String decrypt(String message, String secret) {
        try {
            
            Logging.printLog("CRX", "Decrypting message of length " + message.length() + " with a secret of length " + secret.length() + ".");
            
            byte[] secretByteArray = MessageDigest.getInstance("SHA-1").digest(secret.getBytes("UTF-8"));
            secretByteArray = Arrays.copyOf(secretByteArray, 16);
            SecretKeySpec secretKey = new SecretKeySpec(secretByteArray, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            
            return new String(cipher.doFinal(Base64.getDecoder().decode(message)));
            
        } catch (Exception e) {
            Logging.printError("Failed to decrypt a message.");
            return null;
        }
    }
    
    public static String decrypt(String message, BigInteger secret) {
        return decrypt(message, String.valueOf(secret));
    }
    
}
