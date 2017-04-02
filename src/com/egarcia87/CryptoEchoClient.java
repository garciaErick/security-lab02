package com.egarcia87;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoEchoClient {
    // This code originally was written from a piece of code written 
    // by Yoonsik Cheon at least 10 years ago.
    // It was rewritten several times by Luc Longpre over the years and
    // may have reached a state that has only little resemblance to the original code.
    // This version used for Computer Security, Spring 2017.    
    public static void main(String[] args) {

        String host;
        Scanner userInput = new Scanner(System.in);
        if (args.length > 0) {
            host = args[0];
        } else {
            System.out.println("Enter the server's address: (IP address or \"localhost\")");
            host = userInput.nextLine();
        }
        try {
            Socket socket = new Socket(host, 8008);
            // in and out for socket communication using strings
            BufferedReader in
                    = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println(in.readLine());
            PrintWriter out
                    = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            // We could use Base64 encoding and communicate with strings using in and out
            // However, we show here how to send and receive serializable java objects
            ObjectOutputStream objectOutput = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInput = new ObjectInputStream(socket.getInputStream());
            // read the file of random bytes from which we can derive an AES key
            byte[] randomBytes;
            try {
                FileInputStream fis = new FileInputStream("randomBytes");
                randomBytes = new byte[fis.available()];
            } catch (Exception e) {
                System.out.println("problem reading the randomBytes file");
                return;
            }
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");

            // we will use AES encryption, CBC chaining and PCS5 block padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            // the initialization vector was generated randomly
            // transmit the initialization vector to the server
            // no need to encrypt the initialization vector
            // send the vector as an object
            byte[] iv = cipher.getIV();           
            objectOutput.writeObject(iv);

            // get the initialization vector for decryption from the server
            iv = (byte[]) objectInput.readObject();
            // another cipher decryption with the same type of transformation
            Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // initialize with a specific vector instead of a random one
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            System.out.println("Starting messages to the server. Type messages, type BYE to end");
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedByte = cipher.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedByte);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Receive the reply from the server and print it
                    // get the encrypted bytes from the server as an object
                    encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    String str = new String(decryptCipher.doFinal(encryptedByte));

                    System.out.println(str);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
