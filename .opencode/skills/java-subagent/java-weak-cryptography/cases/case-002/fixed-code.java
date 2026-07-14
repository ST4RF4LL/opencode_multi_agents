import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class TokenEncryptor {
    private static final int IV_LEN = 12;
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public TokenEncryptor(SecretKey key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[IV_LEN];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);
        return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
    }
}
