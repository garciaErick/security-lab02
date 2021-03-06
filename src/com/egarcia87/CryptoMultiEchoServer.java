package com.egarcia87;

import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoMultiEchoServer {
    // This code originally was written from a piece of code written 
    // by Yoonsik Cheon at least 10 years ago.
    // It was rewritten several times by Luc Longpre over the years.
    // This version used for Computer Security, Spring 2017.    
    public static void main(String[] args) {

        System.out.println("CryptoMultiEchoServer started.");
        int sessionID = 0; // assign incremental session ids to each client connection

        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("MultiEchoServer stopped.");
    }

    private static class ClientHandler extends Thread {

        protected Socket incoming;
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {
                // in and out for socket communication using strings
                BufferedReader in
                        = new BufferedReader(
                                new InputStreamReader(incoming.getInputStream()));
                PrintWriter out
                        = new PrintWriter(
                                new OutputStreamWriter(incoming.getOutputStream()));
                // send hello to client
                out.print("Hello! This is Java CryptoMultiEchoServer. ");
                out.println("Enter BYE to exit.");
                out.flush();

                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects                    
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                // read the file of random bytes from which we can derive an AES key
                byte[] randomBytes;
                try {
                    FileInputStream fis = new FileInputStream("randomBytes");
                    randomBytes = new byte[fis.available()];
                } catch (Exception e) {
                    System.out.println("problem reading the randomBytes file");
                    return;
                }
                // get the initialization vector from the client
                // each client will have a different vector
                byte[] iv = (byte[]) objectInput.readObject();
                // generate an AES key derived from randomBytes array
                SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");

                // we will use AES encryption, CBC chaining and PCS5 block padding
                Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                // initialize with a specific vector instead of a random one for decryption
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                // another cipher for encryption with the same type of transformation
                Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                // the initialization vector was generated randomly
                iv = encryptCipher.getIV();
                // transmit the initialization vector to the client
                // no need to encrypt the initialization vector
                // send the vector as an object to the client
                objectOutput.writeObject(iv);

                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (;;) {
                    // get the encrypted bytes from the client as an object
                    byte[] encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    String str = new String(decryptCipher.doFinal(encryptedByte));
                    // print the message received from the client
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        //the client already closed the connection, give no reply
                        break;
                    }
                    // reply to the client with an echo of the string
                    str = "Echo: " + str;
                    // Encrypt the message
                    encryptedByte = encryptCipher.doFinal(str.getBytes());
                    // Send encrypted message as an object to the client
                    objectOutput.writeObject(encryptedByte);

                }
                System.out.println("Session " + id + " ended.");
                incoming.close();
            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}
