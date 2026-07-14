import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class N05_ManagedKeyNoHardcode {
    public byte[] safe(SecretKey managedKey, byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, managedKey, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }
}
