import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoService {
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LEN = 12;
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public CryptoService(SecretKey key) {
        this.key = key;
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[IV_LEN];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buf = ByteBuffer.allocate(iv.length + ct.length);
        buf.put(iv);
        buf.put(ct);
        return Base64.getEncoder().encodeToString(buf.array());
    }
}
