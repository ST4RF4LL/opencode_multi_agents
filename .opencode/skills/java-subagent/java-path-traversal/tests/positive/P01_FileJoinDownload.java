import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class P01_FileJoinDownload {
    public InputStream vulnerable(File baseDir, String filename) throws Exception {
        File target = new File(baseDir, filename);
        return new FileInputStream(target);
    }
}
