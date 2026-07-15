import java.io.FileInputStream;
import java.io.InputStream;

public class P05_StringConcatPath {
    public InputStream vulnerable(String baseDir, String filename) throws Exception {
        String path = baseDir + "/" + filename;
        return new FileInputStream(path);
    }
}
