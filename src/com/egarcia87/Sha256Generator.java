package com.egarcia87;

import java.security.MessageDigest;

public class Sha256Generator {

	public Sha256Generator() {
	}

	public byte[] getHash(byte[] toHash) throws Exception {
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(toHash);
		return hash.digest();
	}
}
