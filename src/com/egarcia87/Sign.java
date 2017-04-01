package com.egarcia87;
import java.io.*;
import java.security.*;
import java.util.Base64;

class Sign {

    public void sign(String privateKeyFileName, String messageToSign) {
        // Written by Luc Longpre for Computer Security, Spring 2017

        File file;
        PrivateKey privKey;
        Signature sig;
        byte[] signature;

        System.out.println("Signing the message: \""+messageToSign+"\"");

        // Read private key from file
        privKey = PemUtils.readPrivateKey(privateKeyFileName);

        try {
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privKey);
            sig.update(messageToSign.getBytes());
            signature = sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Error attempting to sign");
            return;
        }
        file = new File("signature.txt");
        try (PrintWriter output = new PrintWriter(file)) {
            output.print(Base64.getEncoder().encodeToString(signature));
        } catch (Exception e) {
            System.out.println("Could not create signature file");
        }
    }
}
