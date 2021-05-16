package com.company;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Main {

    public static String readFileString(){
        String text = "";
        try{
            text = new String(Files.readAllBytes(Paths.get("/Users/tarkanbatar/Desktop/long_text.txt")));   // reads the txt file that given directory
        } catch (IOException e) {
            e.printStackTrace();
        }
        return text;
    }

    public static byte[] Create_Digital_Signature(byte[] input, Key privKey) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");     // Creating SHA256 signature
        signature.initSign((PrivateKey) privKey);     //initializing sign
        signature.update(input);
        return signature.sign();
    }

    public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey publicKey) throws Exception { // this function verifies the digital signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);  //verifying with given public key
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

    public static final String AES = "AES";
    public static void main(String[] args) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);      //key size

        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();     // creating public key
        Key pri = kp.getPrivate();    //creating private key

        System.out.println("Public RSA Key: " + pub + "\n");
        System.out.printf("Private RSA Key: " + pri + "\n");
            // 1st QUESTION //

        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator1 = KeyGenerator.getInstance(AES);
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance(AES);       // two different AES key generator created

        keyGenerator1.init(128,secureRandom);             // first generator initialized with size of 128
        keyGenerator2.init(256,secureRandom);             // second generator initialized with size of 256

        SecretKey symKey1 = keyGenerator1.generateKey();      //key1 generated
        SecretKey symKey2 = keyGenerator2.generateKey();      //key2 generated

        String symKey1Temp = symKey1.toString();          //key1 changed to string
        String symKey2Temp = symKey2.toString();          //key2 changed to string

        int symKey1TempLength= symKey1Temp.length();      //getting the size of key1
        int symKey2TempLength= symKey2Temp.length();      //getting the size of key2

        String symKey1Prnt = symKey1Temp.substring(32,symKey1TempLength);     // getting a part of key1
        String symKey2Prnt = symKey2Temp.substring(32,symKey2TempLength);     // getting a part of key2

        String binary = String.format("%040x", new BigInteger(1,symKey1Temp.getBytes("UTF-8")));      // format change
        String binary2 = String.format("%040x", new BigInteger(1,symKey2Temp.getBytes("UTF-8")));     // format change

        System.out.println("128-bit Symmetric key: " + symKey1 + "\n     " + " changing part " + symKey1Prnt + "\n");
        System.out.println("256-bit Symmetric key: " + symKey2 + "\n     " + " changing part " + symKey2Prnt + "\n");

        System.out.println("Symmetric key Hexadecimal (128-bit): " + binary + "\n");
        System.out.println("Symmetric key Hexadecimal (256-bit): " + binary2 + "\n");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,pub);         // cipher created in encryption mode with public key

        byte[] encrypted1 = cipher.doFinal(symKey1Temp.getBytes());
        byte[] encrypted2 = cipher.doFinal(symKey2Temp.getBytes());
        String encryptedKey1 = new String(Base64.getEncoder().encode(encrypted1));
        String encryptedKey2 = new String(Base64.getEncoder().encode(encrypted2));        // encryption process done

        System.out.println("Encrypted Key (128-bit): " + encryptedKey1 + "\n");
        System.out.println("Encrypted Key (256-bit): " +encryptedKey2 + "\n");

        Cipher cipherDecrypt = Cipher.getInstance("RSA");
        cipherDecrypt.init(Cipher.DECRYPT_MODE,pri);          // cipher created in encryption mode with private key

        byte[] decrypted1 = cipherDecrypt.doFinal(encrypted1);
        byte[] decrypted2 = cipherDecrypt.doFinal(encrypted2);        // decryption process done

        System.out.println("Decrypted Key (128-bit): " + decrypted1 + "\n");
        System.out.println("Decrypted Key (256-bit): " + decrypted2 + "\n");
                // 2nd QUESTION //

        String longText = readFileString();       // text file read
        System.out.println("Text: " + longText);
        MessageDigest md = MessageDigest.getInstance("SHA-256");  // sha256 message digest created
        byte[] convMd  = md.digest(longText.getBytes());          // text message converted to byte array
        BigInteger num = new BigInteger(1,convMd);
        StringBuilder hexText = new StringBuilder(num.toString(16));      // hexadecimal text created by normal text to converting hexadecimal
        while (hexText.length() < 32){
            hexText.insert(0, '0');       //'0' added in hexadecimal text
        }

        byte[] signature = Create_Digital_Signature(convMd, pri);      // digital signature created
        String signatureConv = signature.toString();              // digital signature converted to string
        String signConv = String.format("%040x", new BigInteger(1,signatureConv.getBytes("UTF-8")));  // digital signature formatted

        String result = hexText.toString();   // converting hexadecimal result to string
        System.out.println("\nHexadecimal text:" + result + "\n");

        System.out.println("Signature Value: " + signConv + "\n");
        System.out.println("Verification: " + Verify_Digital_Signature(convMd, signature, (PublicKey) pub));      // digital signature check and verification in print line
                //3rd QUESTION //

        SecureRandom secureRandom2 = new SecureRandom();
        KeyGenerator keyGenerator3 = KeyGenerator.getInstance("AES");

        keyGenerator3.init(128,secureRandom2);
        keyGenerator3.init(256,secureRandom2);

        SecretKey symKey3 = keyGenerator3.generateKey();        // creating 128-bit AES key
        SecretKey symKey4 = keyGenerator3.generateKey();        // creating 256-bit AES key

        FileInputStream fis = new FileInputStream("/Users/tarkanbatar/Desktop/hw1.jpg");
        byte imgData[] = new byte[fis.available()];         // getting image from directory and making it byte array
        String imgDataS = imgData.toString();

        String initVector = "initVectorOfAlgo";     //initial vector
        System.out.println("Image Data: " + imgDataS + "\n");       // printing image data

        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));     // creating initial vector spec
        Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");         // creating AES/CBC cipher
        cipher.init(Cipher.ENCRYPT_MODE, symKey3, iv);      // cipher turned encryption mode

        byte[] encryptedImg = cipher2.doFinal(imgDataS.getBytes());  // image data encrypted with 128 bit
        System.out.println("Encrypted Image (with 128-bit CBC): " + Base64.getEncoder().encode(encryptedImg) + "\n");

        cipher2.init(Cipher.DECRYPT_MODE, symKey3, iv);      // image data decrypted with 128 bit
        byte[] decryptedImg = cipher2.doFinal(Base64.getDecoder().decode(encryptedImg));
        System.out.println("Decrypted Image: " + Base64.getDecoder().decode(decryptedImg));

        cipher2.init(Cipher.ENCRYPT_MODE,symKey4,iv);        // image data encrypted with 256 bit
        byte[] encryptedImg2 = cipher2.doFinal(imgDataS.getBytes());
        System.out.println("Encrypted Image (with 256-bit CBC): " + Base64.getEncoder().encode(encryptedImg2) + "\n");

        cipher2.init(Cipher.DECRYPT_MODE,symKey4,iv);        // image data decrypted with 256 bit
        byte[] decryptedImg2 = cipher2.doFinal(Base64.getDecoder().decode(encryptedImg2));
        System.out.println("Decrypted Image: " + Base64.getDecoder().decode(decryptedImg2));



    }
}
