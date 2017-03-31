package com.egarcia87;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Verify {

    public static void main(String[] args) {
        // Written by Luc Longpre for Computer Security, Spring 2017        
        File file;
        PublicKey pubKey;
        String signature;
        String messageSigned = "Hello!";
        
        System.out.println("Verifying the signature of: \""+messageSigned+"\"");

        // Read public key from file
        pubKey = PemUtils.readPublicKey("publicKey.pem");

        // Read signature from file
        try {
            file = new File("signature.txt");
            Scanner input = new Scanner(file);
            signature = input.nextLine();
        } catch (FileNotFoundException ex) {
            System.out.println("Could not open signature file: " + ex);
            return;
        }

        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(messageSigned.getBytes());
            if (sig.verify(Base64.getDecoder().decode(signature))) {
                System.out.println("Signature verification succeeded");
            } else {
                System.out.println("Signature verification failed");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("problem verifying signature: " + e);
        }
    }
}
