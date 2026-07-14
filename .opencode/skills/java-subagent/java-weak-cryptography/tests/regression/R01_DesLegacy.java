import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Regression: DES must remain detected as weak-algo. */
public class R01_DesLegacy {
    public byte[] mustDetect(byte[] key8, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key8, "DES"));
        return c.doFinal(data);
    }
}
