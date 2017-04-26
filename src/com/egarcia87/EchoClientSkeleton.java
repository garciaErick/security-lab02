package com.egarcia87;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.Random;

@SuppressWarnings("Duplicates")
public class EchoClientSkeleton {
	// This code includes socket code originally written
	// by Dr. Yoonsik Cheon at least 10 years ago.
	// This version used for Computer Security, Spring 2017.
	public static void main(String[] args) throws Exception {

		String host = "172.19.154.68";
		BufferedReader in; // for reading strings from socket
		PrintWriter out;   // for writing strings to socket
		ObjectInputStream objectInput;   // for reading objects from socket
		ObjectOutputStream objectOutput; // for writing objects to socket
		Cipher cipherDec, cipherEnc;
		byte[] clientRandomBytes;
		byte[] serverRandomBytes;
		PublicKey[] pkpair = {null, null};
		String signature = "";
		Socket socket;
		// Handshake
		try {
			// socket initialization
			socket = new Socket(host, 8008);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
		} catch (IOException e) {
			System.out.println("socket initialization error");
			return;
		}
		// Send hello to server
		out.println("hello");
		out.flush();
		// Receive Server certificate
		// Will need to verify the certificate and extract the Server public keys
		try {
			String contents = "";
			String line = in.readLine();
			Boolean gotEncryptionKey = false;
			String encryptionPublicKeyString = "";
			String signaturePublicKeyString = "";
			String tmpContents = "";
			while (!"-----END SIGNATURE-----".equals(line)) {
				if ("-----BEGIN PUBLIC KEY-----".equals(line))
					contents += line + "\r\n";
				if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
					if (!"-----BEGIN SIGNATURE-----".equals(line))
						contents += line + "\r\n";
					line = in.readLine();
				} else {
					line = in.readLine();
					while (!"-----END PUBLIC KEY-----".equals(line)) {
						contents += line + "\r\n";
						tmpContents += line;
						line = in.readLine();
					}
					if (!gotEncryptionKey) {
						encryptionPublicKeyString = tmpContents;
						gotEncryptionKey = true;
					} else
						signaturePublicKeyString = tmpContents;
					tmpContents = "";
				}
				if ("-----BEGIN SIGNATURE-----".equals(line)) {
					signature = in.readLine();
				}
			}
//			System.out.println("Encryption Pk\n" + encryptionPublicKeyString);
//			System.out.println("\nSignature Pk\n" + signaturePublicKeyString);
//			System.out.println("\nSignature \n" + signature);
			PublicKey encryptionPk = getPublicKey(encryptionPublicKeyString);
			PublicKey signaturePk = getPublicKey(signaturePublicKeyString);
			pkpair[0] = encryptionPk;
			pkpair[1] = signaturePk;
			PublicKey CApk = PemUtils.readPublicKey("files/CApublicKey.pem");
			verifySignature(signature, contents, CApk);

		} catch (IOException e) {
			System.out.println("problem reading the certificate from server");
			return;
		}

		try {
			// read and send certificate to server
			File file = new File("files/certificate.txt");
			Scanner input = new Scanner(file);
			String line;
			while (input.hasNextLine()) {
				line = input.nextLine();
				out.println(line);
			}
			out.flush();
		} catch (FileNotFoundException e) {
			System.out.println("certificate file not found");
			return;
		}
		try {
			// initialize object streams
			objectOutput = new ObjectOutputStream(socket.getOutputStream());
			objectInput = new ObjectInputStream(socket.getInputStream());
			// receive encrypted random bytes from server
			byte[] encryptedBytes = (byte[]) objectInput.readObject();
			// receive signature of hash of random bytes from server
			byte[] signatureBytes = (byte[]) objectInput.readObject();
			// will need to verify the signature and decrypt the random bytes

			Decrypt decryptor = new Decrypt();
			serverRandomBytes = decryptor.getDecryptedBytes("files/Garcia_PalominoClientEncryptPrivate.pem", encryptedBytes);
			
			Sha256Generator sha256Generator = new Sha256Generator();
			byte[] hashedDecryptedBytes = sha256Generator.getHash(serverRandomBytes);

			Verify verifier = new Verify();
			verifier.verify(pkpair[1], hashedDecryptedBytes, signatureBytes);
		} catch (IOException | ClassNotFoundException ex) {
			System.out.println("Problem with receiving random bytes from server");
			return;
		}

		// generate random bytes for shared secret
		clientRandomBytes = new byte[8];
		new Random().nextBytes(clientRandomBytes);
		try {
			Encrypt encryptor = new Encrypt();
			byte[] encryptedBytes = encryptor.getEncryptedBytes(pkpair[0], clientRandomBytes);
			objectOutput.writeObject(encryptedBytes);

			Sha256Generator sha256Generator = new Sha256Generator();
			byte [] hashedBytes = sha256Generator.getHash(clientRandomBytes);
			byte[] signatureBytes = Sign.getSignature("files/Garcia_PalominoClientSignPrivate.pem", hashedBytes);
			objectOutput.writeObject(signatureBytes);

			System.out.println("Shared secret sent.");
		} catch (IOException e) {
			System.out.println("error computing or sending the signature for random bytes");
			return;
		}

		// initialize the shared secret with all zeroes
		// will need to generate from a combination of the server and
		// the client random bytes generated
		byte[] sharedSecret = new byte[16];
		System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
		System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
		try {
			SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");

			cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// get the initialization vector for decryption from the server
			byte[] iv = (byte[]) objectInput.readObject();
			// initialize with a specific vector instead of a random one
			cipherDec.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

			cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// generate an AES key derived from randomBytes array
			cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
			iv = cipherEnc.getIV();
			objectOutput.writeObject(iv);
			System.out.println("Ciphers initiated.");
		} catch (IOException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException e) {
			System.out.println("error setting up the AES encryption");
			return;
		}

		try {
			// Encrypted communication
			System.out.println("Starting messages to the server. Type messages, type BYE to end");
			Scanner userInput = new Scanner(System.in);
			boolean done = false;
			while (!done) {
				// Read message from the user
				String userStr = userInput.nextLine();
				// Encrypt the message
				byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
				// Send encrypted message as an object to the server
				objectOutput.writeObject(encryptedBytes);
				// If user says "BYE", end session
				if (userStr.trim().equals("BYE")) {
					System.out.println("client session ended");
					done = true;
				} else {
					// Wait for reply from server,
					encryptedBytes = (byte[]) objectInput.readObject();

					String str = new String(cipherDec.doFinal(encryptedBytes));

					System.out.println(str);
				}
			}
		} catch (IllegalBlockSizeException | BadPaddingException
				| IOException | ClassNotFoundException e) {
			System.out.println("error in encrypted communication with server");
		}
	}

	private static PublicKey getPublicKey(String publicKeyString) {
		PublicKey pKey = null;
		byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
		X509EncodedKeySpec spec
				= new X509EncodedKeySpec(keyBytes);
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pKey = kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("public key recovery exception");
			return null;
		}
		return pKey;
	}

	private static void verifySignature(String signature, String contents, PublicKey signaturePk) {
		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(signaturePk);
			sig.update(contents.getBytes());
			// output the result of the verification
			// System.out.println("Signature:"+signature);
			if (sig.verify(Base64.getDecoder().decode(signature))) {
				System.out.println("Signature verification succeeded");
			} else {
				System.out.println("Signature verification failed");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			System.out.println("error occurred while trying to verify signature" + e);
		}
	}
}
