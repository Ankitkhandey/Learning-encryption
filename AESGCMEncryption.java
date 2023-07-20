import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public class AESGCMEncryption {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final String AES = "AES";

    public static final Integer GCMLENGTH = 128;
    public static final String IV = "staticIV";
    public static final String KEY = "snadjfdsfnesjfnsjdfsndlfknsdlfks";

    public static String encrypt(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(cipherText);
    }

    public static String decrypt(String cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCMLENGTH, IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        String plainText = "Ankit Khandey";
        String cipherText = encrypt(plainText);
        String decryptedText = decrypt(cipherText);
        System.out.println("Plain text: " + plainText);
        System.out.println("Cipher text: " + cipherText);
        System.out.println("Decrypted text by utkarsh: " + decryptedText);
    }

}
