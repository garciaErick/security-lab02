package com.egarcia87;

public class Main {

	public static void main(String[] args) {
		CreatePemKeys pemKeysGenerator = new CreatePemKeys();
//		pemKeysGenerator.createPemKeys("files/Garcia_PalominoClientSign");
//		pemKeysGenerator.createPemKeys("files/Garcia_PalominoClientEncrypt");
//		pemKeysGenerator.createPemKeys("files/Garcia_PalominoServerSign");
//		pemKeysGenerator.createPemKeys("files/Garcia_PalominoServerEncrypt");

		Encrypt encryptor = new Encrypt();
		Decrypt decryptor = new Decrypt();

		System.out.println("Encryption:");
		encryptor.encrypt("files/Garcia_PalominoClientEncryptPublic.pem", "Abner Palomino & Erick Garcia, 02/04/2017");
		System.out.println("\nDecryption:");
		decryptor.decrypt("files/Garcia_PalominoClientEncryptPrivate.pem", "encryptedMessage.txt");

		Sign signer = new Sign();
		Verify verifier = new Verify();

		System.out.println("\nSignature:");
		signer.sign("files/Garcia_PalominoClientSignPrivate.pem", "Abner Palomino & Erick Garcia, 02/04/2017, 02/04/2017");

		System.out.println("\nVerification:");
		verifier.verify("files/Garcia_PalominoClientSignPublic.pem", "Sample Message that has had its contents altered");
		verifier.verify("files/Garcia_PalominoClientSignPublic.pem", "Abner Palomino & Erick Garcia, 02/04/2017, 02/04/2017");

		VerifyCert certificateVerifier = new VerifyCert();
		System.out.println("\nVerifying Certificate with Longpre client certificate:");
		certificateVerifier.verifyCertificate("files/CApublicKey.pem", "files/client1Certificate.txt");
		System.out.println("\nVerifying Certificate with local client certificate:");
		certificateVerifier.verifyCertificate("files/CApublicKey.pem", "files/certificate.txt");


	}
}
