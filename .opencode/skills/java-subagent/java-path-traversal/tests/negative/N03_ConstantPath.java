import java.io.FileInputStream;
import java.io.InputStream;

public class N03_ConstantPath {
    public InputStream safe() throws Exception {
        return new FileInputStream("/var/app/static/logo.png");
    }
}
