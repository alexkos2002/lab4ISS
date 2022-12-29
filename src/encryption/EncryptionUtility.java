package encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class EncryptionUtility {

    private static final int SAFE_PUBLIC_EXP_TO_MODULE_RATIO = 100;

    public static class RSAKeyPair {
        private RSAKey privateKey;
        private RSAKey publicKey;

        public RSAKeyPair(RSAKey privateKey, RSAKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public RSAKeyPair() {

        }

        public RSAKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(RSAKey privateKey) {
            this.privateKey = privateKey;
        }

        public RSAKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(RSAKey publicKey) {
            this.publicKey = publicKey;
        }
    }

    public static class RSAKey {
        private int module;
        private int exp;

        public RSAKey(int module, int exp) {
            this.module = module;
            this.exp = exp;
        }

        public RSAKey() {
        }

        public int getModule() {
            return module;
        }

        public void setModule(int modulo) {
            this.module = modulo;
        }

        public int getExp() {
            return exp;
        }

        public void setExp(int exp) {
            this.exp = exp;
        }
    }

    public static byte[] encryptSP(byte[] data, byte[] key) {
        int curBlockStartIdx = 0;
        int dataLength = data.length;
        int keyLength = key.length;
        byte[] result = new byte[dataLength];
        int i;
        while (dataLength - curBlockStartIdx >= keyLength) {
            for (i = 0; i < keyLength; i++) {
                result[curBlockStartIdx + key[i]] = data[curBlockStartIdx + i];
            }
            curBlockStartIdx += keyLength;
        }

        int bytesRemain = dataLength - curBlockStartIdx;
        byte[] partialKey = new byte[bytesRemain];
        Arrays.fill(partialKey, (byte) -1);

        byte curPos = 0;
        for (i = 0; i < bytesRemain; i++) {
            curPos = (byte) (key[i] % bytesRemain);
            if (linearSearch(partialKey, curPos) != -1) {
                do {
                    curPos++;
                    if (curPos >= bytesRemain) {
                        curPos = 0;
                    }
                } while (linearSearch(partialKey, curPos) != -1);
            }
            partialKey[i] = curPos;
        }
        for (i = 0; i < bytesRemain; i++) {
            result[curBlockStartIdx + partialKey[i]] = data[curBlockStartIdx + i];
        }
        return result;
    }

    public static byte[] decryptSP(byte[] encryptedData, byte[] key) {
        int curBlockStartIdx = 0;
        int dataLength = encryptedData.length;
        int keyLength = key.length;
        byte[] result = new byte[dataLength];
        int i;
        while (dataLength - curBlockStartIdx >= keyLength) {
            for (i = 0; i < keyLength; i++) {
                result[curBlockStartIdx + linearSearch(key, (byte) i)] = encryptedData[curBlockStartIdx + i];
            }
            curBlockStartIdx += keyLength;
        }

        int bytesRemain = dataLength - curBlockStartIdx;
        byte[] partialKey = new byte[bytesRemain];
        Arrays.fill(partialKey, (byte) -1);

        byte curPos = 0;
        for (i = 0; i < bytesRemain; i++) {
            curPos = (byte) (key[i] % bytesRemain);
            if (linearSearch(partialKey, curPos) != -1) {
                do {
                    curPos++;
                    if (curPos >= bytesRemain) {
                        curPos = 0;
                    }
                } while (linearSearch(partialKey, curPos) != -1);
            }
            partialKey[i] = curPos;
        }

        for (i = 0; i < bytesRemain; i++) {
            result[curBlockStartIdx + linearSearch(partialKey, (byte) i)] = encryptedData[curBlockStartIdx + i];
        }
        return result;
    }

    public static byte[] generateSPKey(int keyLength) {
        List<Byte> keyList = new ArrayList<>();
        for (int pos = 0; pos < keyLength; pos++) {
            keyList.add((byte) pos);
        }
        Collections.shuffle(keyList);
        byte[] key = new byte[keyLength];
        for (int i = 0; i < keyLength; i++) {
            key[i] = keyList.get(i);
        }
        return key;
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher RSACipher = Cipher.getInstance("RSA");
        RSACipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encTextBytes = RSACipher.doFinal(data);
        return encTextBytes;
    }

    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher RSACipher = Cipher.getInstance("RSA");
        RSACipher.init(Cipher.DECRYPT_MODE,
                privateKey);
        return RSACipher.doFinal(encryptedData);
    }

    public static KeyPair generateRSAKeys(int keyModuleLength) throws NoSuchAlgorithmException {
        KeyPairGenerator RSAKPGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKPGenerator.initialize(keyModuleLength);
        return RSAKPGenerator.generateKeyPair();
    }

    public static BigInteger[] encryptRSA(byte[] data, RSAKey publicKey) {
        int dataLength = data.length;
        BigInteger N = BigInteger.valueOf(publicKey.getModule());
        int e = publicKey.getExp();
        BigInteger[] result = new BigInteger[dataLength];
        for (int i = 0; i < dataLength; i++) {
            result[i] = (BigInteger.valueOf(data[i]).pow(e)).mod(N);
        }
        return result;
    }

    public static byte[] decryptRSA(BigInteger[] encryptedData, RSAKey privateKey) {
        int dataLength = encryptedData.length;
        BigInteger N = BigInteger.valueOf(privateKey.getModule());
        int d = privateKey.getExp();
        byte[] result = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            result[i] = (((encryptedData[i]).pow(d)).mod(N).toByteArray())[0];
        }
        return result;
    }

    public static RSAKeyPair generateRSAKeys(int p, int q) {
        int e, d;
        int N = p * q;
        int T = (p - 1) * (q - 1);

        //calculate public exponent.
        for (e = 2; e < T; e++) {
            if (getEuclidianGCD(e, T) == 1 && N / e < SAFE_PUBLIC_EXP_TO_MODULE_RATIO) {
                break;
            }
        }

        //calculate private exponent
        int ed;
        int n = 1;
        while (((ed = (T * n + 1)) % e) != 0) {
            n++;
        }
        d = ed / e;
        RSAKey publicKey = new RSAKey(N, e);
        RSAKey privateKey = new RSAKey(N, d);
        return new RSAKeyPair(privateKey, publicKey);
    }

    /**
     * Calculates the greatest common divider(GCD) of two integers via Euclidian algorithm.
     *
     * @param num1 - first number.
     * @param num2 - second number.
     * @return GCD of num1 and num2.
     */
    private static int getEuclidianGCD(int num1, int num2) {
        if (num1 == 0) {
            return num2;
        } else {
            return getEuclidianGCD(num2 % num1, num1);
        }
    }

    private static int linearSearch(byte[] array, byte element) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] == element) {
                return i;
            }
        }
        return -1;
    }
}
