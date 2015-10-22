import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.ibe.BFCipher;
import uk.ac.ic.doc.jpair.ibe.BFCtext;
import uk.ac.ic.doc.jpair.ibe.key.BFUserPrivateKey;
import uk.ac.ic.doc.jpair.ibe.key.BFUserPublicKey;
import uk.ac.ic.doc.jpair.pairing.PairingFactory;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Created by Jacob on 10/21/2015.
 */
public class Demo1 {
    public static void main(String[] args) {
        //Setup the encryption scheme - this part goes on the server
        SecureRandom random = new SecureRandom();
        Pairing pair = PairingFactory.ssTate(128, 512, random);
        BFCipher cipher = new BFCipher();
        KeyPair masterPair = cipher.setup(pair, random);

        //Grab a private/public key from the scheme with a given ID - query the server for these (see below)
        KeyPair userPair = cipher.extract(masterPair, "testName@cpp.edu", random);
        BFUserPublicKey publicKey = (BFUserPublicKey) userPair.getPublic();
        BFUserPrivateKey privateKey = (BFUserPrivateKey) userPair.getPrivate();

        //Grab some test input to encrypt with a person's public key
        Scanner kb = new Scanner(System.in);
        System.out.print("Enter a string to encrypt: ");
        String testLine = kb.nextLine();
        kb.close();

        //Encrypt and print - query the server for the public key
        BFCtext cipherText = cipher.encrypt(publicKey, testLine.getBytes(), random);
        System.out.println("Ciphertext: ");
        System.out.println("U: " + cipherText.getU()
                + "\nV: " + new String(cipherText.getV())
                + "\nW: " + new String(cipherText.getW()));

        //Decrypt and print - query the server for the private key AND DISALLOW FUTURE REQUESTS
        byte[] plainText = cipher.decrypt(cipherText, privateKey);
        System.out.println();
        System.out.println("Decrypted plaintext: ");
        System.out.println(new String(plainText));
    }
}
