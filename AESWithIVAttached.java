import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AES256WithAttachedIV2 {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final String AES = "AES";

    public static final Integer GCMLENGTH = 128;
    public static final String KEY = "snadjfdsfnesjfnsjdfsndlfknsdlfks";

    public static String encrypt(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        byte[] iv = generateIV();

        // encode the concatenated byte array as a Base64 string
        Base64.Encoder encoder = Base64.getEncoder();

        System.out.println("IV in encryption: " + encoder.encodeToString(iv));
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));

        // concatenate IV and ciphertext as byte arrays
        byte[] ivAndCipherText = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
        System.arraycopy(cipherText, 0, ivAndCipherText, iv.length, cipherText.length);


        System.out.println("IV and cipher "+ encoder.encodeToString(ivAndCipherText));
        return encoder.encodeToString(ivAndCipherText);
    }

    public static String decrypt(String cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        Base64.Encoder encoder = Base64.getEncoder();

        // decode the concatenated string back into a byte array
        byte[] ivAndCipherText = Base64.getDecoder().decode(cipherText);

        // split the byte array into IV and ciphertext
        byte[] iv = Arrays.copyOfRange(ivAndCipherText, 0, GCMLENGTH / 8);
        System.out.println("IV in decryption: " + encoder.encodeToString(iv));
        byte[] encryptedText = Arrays.copyOfRange(ivAndCipherText, GCMLENGTH / 8, ivAndCipherText.length);

        System.out.println("EncryptedText: " +encoder.encodeToString(encryptedText));

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] plainText = cipher.doFinal(encryptedText);
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
        System.out.println("Plain text: " + plainText);
        String cipherText = encrypt(plainText);
        System.out.println("Cipher text: " + cipherText);
        String decryptedText = decrypt(cipherText);
        System.out.println("Decrypted text: " + decryptedText);
    }

}
