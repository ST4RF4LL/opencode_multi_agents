// Regression: ObjectInputStream on untrusted bytes must remain a sink candidate
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class R01_ObjectInputStreamMustDetect {
    public Object mustDetect(byte[] userBytes) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(userBytes)).readObject();
    }
}
