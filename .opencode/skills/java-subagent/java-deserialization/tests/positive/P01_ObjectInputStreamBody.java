import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class P01_ObjectInputStreamBody {
    public Object vulnerable(byte[] body) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
        return ois.readObject();
    }
}
