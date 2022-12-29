import encryption.EncryptionUtility;
import hashing.HashingUtility;
import io.IOUtility;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class Main {

    private static final int SP_KEY_SIZE = 16;
    public static void main(String[] args) {
        try {
            //4.1
            String hash = HashingUtility.getSHA1HashCode(IOUtility.readFile("message.txt"));
            System.out.println("Hash: " + hash);

            //4.2
            byte[] w = EncryptionUtility.generateSPKey(SP_KEY_SIZE);
            System.out.println("Symmetric key w: " + Arrays.toString(w));
            IOUtility.writeToFile("w.txt", w);

            byte[] encryptedHash = EncryptionUtility.encryptSP(hash.getBytes(), w);
            System.out.println("Encrypted hash bytes: " + Arrays.toString(encryptedHash));
            System.out.println("Encrypted hash: " + new String(encryptedHash));

            //4.3
            KeyPair RSAKeys = EncryptionUtility.generateRSAKeys(1024);
            PublicKey RSAPublicKey = RSAKeys.getPublic();
            PrivateKey RSAPrivateKey = RSAKeys.getPrivate();

            byte[] encW = EncryptionUtility.encryptRSA(w, RSAPublicKey);
            System.out.println("Encrypted key w: " + Arrays.toString(encW));
            IOUtility.writeToFile("encW.txt", encW);

            //4.4
            byte[] decW = EncryptionUtility.decryptRSA(encW, RSAPrivateKey);
            System.out.println("Decrypted key w: " + Arrays.toString(decW));
            IOUtility.writeToFile("decW.txt", decW);

            //4.5
            String decryptedHash = new String(EncryptionUtility.decryptSP(encryptedHash, decW));
            System.out.println("Decrypted hash: " + hash);

            //4.6
            System.out.println(hash.equals(decryptedHash));

            //Custom RSA
            int p = 193, q = 131;
            EncryptionUtility.RSAKeyPair rsaKeys = EncryptionUtility.generateRSAKeys(p, q);
            EncryptionUtility.RSAKey publicKey = rsaKeys.getPublicKey();
            EncryptionUtility.RSAKey privateKey = rsaKeys.getPrivateKey();
            BigInteger[] encryptedW = EncryptionUtility.encryptRSA(IOUtility.readFile("message.txt"), publicKey);
            IOUtility.writeToFile("rsaDecryptedNessage.txt", EncryptionUtility.decryptRSA(encryptedW, privateKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}