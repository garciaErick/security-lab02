package com.egarcia87;
import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;

class Encrypt {

    public static void main(String[] args) {
        // This program reads a public key from file
        // converts a message string to a byte array,
        // encrypts the message with the public key,
        // encodes using Base64 encoding, 
        // and saves the encrypted message.
        // Written by Luc Longpre for Computer Security, Spring 2017
        
        ObjectInputStream objectInput;
        File file;
        PublicKey pubKey;
        Cipher cipher;
        String messageToEncrypt = "Computer Security Spring 2017";
        byte[] encryptedByteArray;
        String encryptedString;

        // Read public key from file
        pubKey = PemUtils.readPublicKey("publicKey.pem");

        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("Could not initialize encryption");
            return;
        }
        System.out.println("The plaintext is: " + messageToEncrypt);
        try {
            encryptedByteArray = cipher.doFinal(messageToEncrypt.getBytes());
            encryptedString = Base64.getEncoder().encodeToString(encryptedByteArray);
            System.out.println("The encrypted string is: " + encryptedString);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Encryption error");
            return;
        }
        file = new File("encryptedMessage.txt");
        try (PrintWriter output = new PrintWriter(file)) {
            output.print(encryptedString);
        } catch (Exception e) {
            System.out.println("Could not create encryptedMessage file");
        }
    }
}
