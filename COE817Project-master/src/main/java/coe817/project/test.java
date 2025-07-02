package coe817.project;

import javax.crypto.SecretKey;

public class test {
    public static void main(String[] args) throws Exception {
        SecretKey Key = Encryption.generateSecretKey("AES");
        String Test = Encryption.encodeKey(Key);
        System.out.println(Test);
    }
}
