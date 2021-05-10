package com.company;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;

public class Main {

//    public static void q1() throws NoSuchAlgorithmException {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(2048);      //key size
//
//        KeyPair kp = kpg.generateKeyPair();
//        Key pub = kp.getPublic();
//        Key pri = kp.getPrivate();
//
//        System.out.println("Public RSA Key: " + pub + "\n");
//        System.out.printf("Private RSA Key: " + pri + "\n");
//    }

    public static final String AES = "AES";
    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);      //key size

        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pri = kp.getPrivate();

        System.out.println("Public RSA Key: " + pub + "\n");
        System.out.printf("Private RSA Key: " + pri + "\n");
            // 1st QUESTION //

        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator1 = KeyGenerator.getInstance(AES);
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance(AES);

        keyGenerator1.init(128,secureRandom);
        keyGenerator2.init(256,secureRandom);

        SecretKey symKey1 = keyGenerator1.generateKey();
        SecretKey symKey2 = keyGenerator2.generateKey();

        String symKey1Temp = symKey1.toString();
        String symKey2Temp = symKey2.toString();

        int symKey1TempLength= symKey1Temp.length();
        int symKey2TempLength= symKey2Temp.length();

        String symKey1Prnt = symKey1Temp.substring(32,symKey1TempLength);
        String symKey2Prnt = symKey2Temp.substring(32,symKey2TempLength);

        String binary = String.format("%040x", new BigInteger(1,symKey1Temp.getBytes("UTF-8")));
        String binary2 = String.format("%040x", new BigInteger(1,symKey2Temp.getBytes("UTF-8")));

        System.out.println("128-bit Symmetric key: " + symKey1 + " changing part " + symKey1Prnt + "\n");
        System.out.println("256-bit Symmetric key: " + symKey2 + " changing part " + symKey2Prnt + "\n");

        System.out.println("Symmetric key Hexadecimal (128-bit): " + binary + "\n");
        System.out.println("Symmetric key Hexadecimal (256-bit): " + binary2 + "\n");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,pub);

        byte[] encrypted1 = cipher.doFinal(symKey1Temp.getBytes());
        byte[] encrypted2 = cipher.doFinal(symKey2Temp.getBytes());
        String encryptedKey1 = new String(Base64.getEncoder().encode(encrypted1));
        String encryptedKey2 = new String(Base64.getEncoder().encode(encrypted2));

        System.out.println(encryptedKey1 + "\n");
        System.out.println(encryptedKey2 + "\n");

        Cipher cipherDecrypt = Cipher.getInstance("RSA");
        cipherDecrypt.init(Cipher.DECRYPT_MODE,pri);

        byte[] decrypted1 = cipherDecrypt.doFinal(encrypted1);
        byte[] decrypted2 = cipherDecrypt.doFinal(encrypted2);

        System.out.println(decrypted1 + "\n");
        System.out.println(decrypted2 + "\n");
                // 2nd QUESTION //
    }
}
