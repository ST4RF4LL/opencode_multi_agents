import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class N05_ConstantInternalBlob {
    private static final byte[] TRUSTED = new byte[] { /* fixed internal */ };

    public Object safe() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(TRUSTED));
        return ois.readObject();
    }
}
