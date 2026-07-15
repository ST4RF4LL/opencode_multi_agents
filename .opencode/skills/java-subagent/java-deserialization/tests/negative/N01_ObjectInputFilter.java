import java.io.ByteArrayInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class N01_ObjectInputFilter {
    private static final ObjectInputFilter FILTER =
        ObjectInputFilter.Config.createFilter("com.example.dto.*;!*");

    public Object safe(byte[] body) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
        ois.setObjectInputFilter(FILTER);
        return ois.readObject();
    }
}
