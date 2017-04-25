package com.egarcia87;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Verify {

	public void verify(String pubicKeyFileName, String messageSigned) {
		// Written by Luc Longpre for Computer Security, Spring 2017
		File file;
		PublicKey pubKey;
		String signature;

		System.out.println("Verifying the signature of: \"" + messageSigned + "\"");

		// Read public key from file
		pubKey = PemUtils.readPublicKey(pubicKeyFileName);

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

	public void verify(PublicKey pubKey, byte[] messageToBeVerified, byte[] signatureBytes) {
		/*
		*	initialize the Signature object with the certificate of the issuer,
		*	call update() with all the bytes of the message,
		* call verify() with the bytes of the signature
		 */
		System.out.println("Verifying the signature of: \"" + signatureBytes + "\"");
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(pubKey);
			sig.update(messageToBeVerified);
			if (sig.verify(signatureBytes)) {
				System.out.println("Signature verification succeeded");
			} else {
				System.out.println("Signature verification failed");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			System.out.println("problem verifying signature: " + e);
		}
	}
}
