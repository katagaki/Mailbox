package com.Mailbox;

import com.Mailbox.Crypto;
import java.math.BigInteger;

public class CryptoTester {
    
    public static void main(String args[]) {
        
        // Generate a shared prime number
        BigInteger p = Crypto.getPrime(2048);
        System.out.print("p: ");
        System.out.println(p);
        
        // Generate a generator
        BigInteger g = Crypto.getPrime(2);
        System.out.print("g: ");
        System.out.println(g);
        
        // Alice calculates her secret
        BigInteger XA = Crypto.getPrime(2048);
        System.out.print("XA: ");
        System.out.println(XA);
        
        // Bob calculates his secret
        BigInteger XB = Crypto.getPrime(2048);
        System.out.print("XB: ");
        System.out.println(XB);
        
        // Alice calculates her public key (shared with Bob)
        BigInteger YA = Crypto.getPublicKey(XA, g, p);
        System.out.print("YA: ");
        System.out.println(YA);
        
        // Bob calculates his public key (shared with Alice)
        BigInteger YB = Crypto.getPublicKey(XB, g, p);
        System.out.print("YB: ");
        System.out.println(YB);
        
        // Alice calculates her shared key
        BigInteger KA = Crypto.getSharedSecret(YA, XB, p);
        System.out.print("KA: ");
        System.out.println(KA);
        
        // Bob calculates his shared key
        BigInteger KB = Crypto.getSharedSecret(YB, XA, p);
        System.out.print("KB: ");
        System.out.println(KB);
        
        // Quick verification to see if the shared keys match
        if (KA.equals(KB)) {
            System.out.println("Keys match: key exchange successful.");
        } else {
            System.out.println("Keys do not match: key exchange failed.");
        }
        
        String encryptedString = Crypto.encrypt("The quick brown fox jumps over the lazy dog.", KA);
        
        System.out.println("Encrypted form of 'The quick brown fox jumps over the lazy dog.':");
        System.out.println(encryptedString);
        System.out.println("Decrypted form of 'The quick brown fox jumps over the lazy dog.':");
        System.out.println(Crypto.decrypt(encryptedString, KA));
        
    }
    
}
