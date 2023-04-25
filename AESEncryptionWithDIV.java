import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AESEncryptionWithDIV {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final String AES = "AES";

    public static final Integer GCMLENGTH = 128;
    public static final String KEY = "snadjfdsfnesjfnsjdfsndlfknsdlfks";

    public static String encrypt(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        byte[] iv = generateIV();
        System.out.println("IV during encryption "+ Arrays.toString(iv));
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(cipherText);
    }

    public static String decrypt(String cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        byte[] iv = generateIV();
        System.out.println("IV during decryption "+ Arrays.toString(iv));
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText, "UTF-8");
    }

    public static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[GCMLENGTH / 8];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        String plainText = "Ankit Khandey";
        String cipherText = encrypt(plainText);
        String decryptedText = decrypt(cipherText);
        System.out.println("Plain text: " + plainText);
        System.out.println("Cipher text: " + cipherText);
        System.out.println("Decrypted text: " + decryptedText);
    }

}
