package com.egarcia87;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Scanner;

class Decrypt {
  
  public void decrypt(String privateKeyFileName, String fileToDecrypt) {
    // This program reads a private key from a file
    // and an encrypted message, decrypts the message
    // and prints it.
    // Written by Luc Longpre for Computer Security, Spring 2017
        
    File file;
    PrivateKey privKey;
    Cipher cipher;
    byte[] decryptedByteArray;
    String encryptedString, decryptedString;
    
    // get the private key from file
    privKey = PemUtils.readPrivateKey(privateKeyFileName);

    // get the encrypted Message
    try{
      file = new File(fileToDecrypt);
      Scanner input = new Scanner(file);
      encryptedString = input.nextLine();
      System.out.println("The encrypted string is: "+encryptedString);
    } catch (Exception e) {
      System.out.println("Could not open encryptedMessage file");
      return;
    }
    
    // decrypt string with private key
    try{
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, privKey);
      decryptedByteArray = Base64.getDecoder().decode(encryptedString); 
      decryptedString = new String(cipher.doFinal(decryptedByteArray));
      System.out.println("The decrypted string is: "+decryptedString);       
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      System.out.println("error while decrypting the message");
    }
  }
}
