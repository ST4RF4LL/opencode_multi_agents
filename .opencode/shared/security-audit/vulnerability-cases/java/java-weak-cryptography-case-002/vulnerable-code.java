// Pattern: AES-GCM with static/hardcoded IV (nonce reuse)
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class TokenEncryptor {
    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FIXED_IV = new byte[] {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };

    public byte[] encrypt(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, FIXED_IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }
}
