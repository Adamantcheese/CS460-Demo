import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.ibe.*;
import uk.ac.ic.doc.jpair.ibe.key.*;
import uk.ac.ic.doc.jpair.pairing.*;

import java.security.*;
import java.util.Scanner;

/**
 * Original created by Jacob on 10/21/2015.
 * Modified by David
 */
public class Demo1 {
    public static void main(String[] args) {
        //Setup the encryption scheme - this part goes on the server
        System.out.println("Initializing PKG and cipher...");
        SecureRandom random = new SecureRandom();
        Pairing pair = PairingFactory.ssTate(128, 512, random);
        System.out.println("\tGenerated random Tate pairing.");
        BFCipher cipher = new BFCipher();
        KeyPair masterPair = cipher.setup(pair, random);
        System.out.println("\tSetup cipher completed.");

        //Grab a private/public key from the scheme with a given ID - query the server for these (see below)
        System.out.print("\nPlease enter the recipient's ID: ");
        Scanner kb = new Scanner(System.in);
        String receiptID = kb.nextLine();
        System.out.println("\tGetting user keys...");
        KeyPair userPair = cipher.extract(masterPair, receiptID, random);
        BFUserPublicKey publicKey = (BFUserPublicKey) userPair.getPublic();
        BFUserPrivateKey privateKey = (BFUserPrivateKey) userPair.getPrivate();
        System.out.println("\tReceived " + receiptID + "'s public key.");

        //Grab some test input to encrypt with a person's public key
        System.out.print("\nEnter a string to encrypt: ");
        String testLine = kb.nextLine();

        //Encrypt and print - query the server for the public key
        System.out.println("\tEncrypting message... ");
        BFCtext cipherText = cipher.encrypt(publicKey, testLine.getBytes(), random);
        System.out.println("\tCiphertext: ");
        System.out.println("\tU: " + cipherText.getU()
                + "\n\tV: " + new String(cipherText.getV())
                + "\n\tW: " + new String(cipherText.getW()));
        kb.nextLine();

        //Decrypt and print - query the server for the private key AND DISALLOW FUTURE REQUESTS
        System.out.println("Decrypting message... ");
        byte[] plainText = cipher.decrypt(cipherText, privateKey);
        System.out.println("\tDecrypted plaintext: " + new String(plainText));
        kb.nextLine();

        //Reencrypt again
        System.out.println("Re-encrypting message... ");
        cipherText = cipher.encrypt(publicKey, plainText, random);
        System.out.println("\tCiphertext: ");
        System.out.println("\tU: " + cipherText.getU()
                + "\n\tV: " + new String(cipherText.getV())
                + "\n\tW: " + new String(cipherText.getW()));
        kb.nextLine();

        //Decrypt again
        System.out.println("Decrypting message ... ");
        plainText = cipher.decrypt(cipherText, privateKey);
        System.out.println("\tDecrypted plaintext: " + new String(plainText));
    }
}
