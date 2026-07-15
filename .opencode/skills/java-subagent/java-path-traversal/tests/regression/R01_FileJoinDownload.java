import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

/** Regression: classic base+filename join must remain a sink candidate. */
public class R01_FileJoinDownload {
    public InputStream mustDetect(File baseDir, String filename) throws Exception {
        File target = new File(baseDir, filename);
        return new FileInputStream(target);
    }
}
