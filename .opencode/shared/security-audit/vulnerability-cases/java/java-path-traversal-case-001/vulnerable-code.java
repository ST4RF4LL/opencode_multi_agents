// Pattern: classic ../ download by filename parameter
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;

public class FileDownloadService {
    private final File baseDir;

    public FileDownloadService(File baseDir) {
        this.baseDir = baseDir;
    }

    public InputStream openForDownload(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        File target = new File(baseDir, filename);
        return new FileInputStream(target);
    }
}
