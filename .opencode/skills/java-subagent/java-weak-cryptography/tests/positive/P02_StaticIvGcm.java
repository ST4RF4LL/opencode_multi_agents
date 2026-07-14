import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class P02_StaticIvGcm {
    private static final byte[] IV = new byte[] {0,1,2,3,4,5,6,7,8,9,10,11};

    public byte[] vulnerable(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, IV));
        return cipher.doFinal(plaintext);
    }
}
