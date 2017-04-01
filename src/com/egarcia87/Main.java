package com.egarcia87;

public class Main {

	public static void main(String[] args) {
		CreatePemKeys pemKeysGenerator = new CreatePemKeys();
		pemKeysGenerator.createPemKeys("Erick-GarciaClientSign");
		pemKeysGenerator.createPemKeys("Erick-GarciaServerEncrypt");

		Encrypt encryptor = new Encrypt();
		Decrypt decryptor = new Decrypt();

		System.out.println("Encryptor:");
		encryptor.encrypt("Erick-GarciaClientSignPublic.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");
		System.out.println("\nDecryptor:");
		decryptor.decrypt("Erick-GarciaClientSignPrivate.pem", "encryptedMessage.txt");

		Sign signer = new Sign();
		Verify verifier = new Verify();

		System.out.println("\nSign:");
		signer.sign("Erick-GarciaClientSignPrivate.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");
		System.out.println("\nVerify:");
		verifier.verify("Erick-GarciaClientSignPublic.pem", "Whatevs");
		verifier.verify("Erick-GarciaClientSignPublic.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");

	}
}
