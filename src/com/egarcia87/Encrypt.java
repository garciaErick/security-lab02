package com.egarcia87;
import com.sun.org.apache.xml.internal.resolver.helpers.PublicId;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

class Encrypt {

    public void encrypt(String pubicKeyFileName, String messageToEncrypt) {
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
        byte[] encryptedByteArray;
        String encryptedString;

        // Read public key from file
        pubKey = PemUtils.readPublicKey(pubicKeyFileName);

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

    public byte[] getEncryptedBytes(PublicKey pubKey, byte[] message) {
        Cipher cipher;
        byte[] encryptedByteArray;

        // get the public key from file
        System.out.println("The string to encrypt is: " + message);

        // decrypt string with public key
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            encryptedByteArray = cipher.doFinal(message);
            System.out.println("The encrypted bytes is: " + encryptedByteArray);
            return encryptedByteArray;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("error while decrypting the message");
        }
        return null;
    }
}
