import hashing.HashingUtility;
import io.IOUtility;

import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        try {
            String hash = HashingUtility.getSHA1HashCode(IOUtility.readFile("message.txt"));
            System.out.println(hash);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}