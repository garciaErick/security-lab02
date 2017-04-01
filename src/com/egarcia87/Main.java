package com.egarcia87;

public class Main {

	public static void main(String[] args) {
		CreatePemKeys pemKeysGenerator = new CreatePemKeys();
		//Comment these lines if you have already generated the pem files and want to test for the CAcertificate
//		pemKeysGenerator.createPemKeys("files/Erick-GarciaClientSign");
//		pemKeysGenerator.createPemKeys("files/Erick-GarciaClientEncrypt");
//		pemKeysGenerator.createPemKeys("files/Erick-GarciaServerSign");
//		pemKeysGenerator.createPemKeys("files/Erick-GarciaServerEncrypt");

		Encrypt encryptor = new Encrypt();
		Decrypt decryptor = new Decrypt();

		System.out.println("Encryptor:");
		encryptor.encrypt("files/Erick-GarciaClientSignPublic.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");
		System.out.println("\nDecryptor:");
		decryptor.decrypt("files/Erick-GarciaClientSignPrivate.pem", "encryptedMessage.txt");

		Sign signer = new Sign();
		Verify verifier = new Verify();

		System.out.println("\nSign:");
		signer.sign("files/Erick-GarciaClientSignPrivate.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");
		System.out.println("\nVerify:");
		verifier.verify("files/Erick-GarciaClientSignPublic.pem", "Whatevs");
		verifier.verify("files/Erick-GarciaClientSignPublic.pem", "Erick Garcia<egarcia87@miners.utep.edu>, 02/04/2017");

		System.out.println("\nVerifying Certificate with Longpre client certificate:");
		VerifyCert certificateVerifier = new VerifyCert();
		certificateVerifier.verifyCertificate("files/CApublicKey.pem", "files/client1Certificate.txt");
		System.out.println("\nVerifying Certificate with local client certificate:");
		certificateVerifier.verifyCertificate("files/CApublicKey.pem", "files/certificate.txt");


	}
}
