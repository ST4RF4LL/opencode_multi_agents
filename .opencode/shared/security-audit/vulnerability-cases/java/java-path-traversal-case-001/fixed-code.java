import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;

public class FileDownloadService {
    private final Path baseDir;

    public FileDownloadService(Path baseDir) {
        this.baseDir = baseDir.toAbsolutePath().normalize();
    }

    public InputStream openForDownload(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        Path target = baseDir.resolve(filename).normalize();
        if (!target.startsWith(baseDir)) {
            throw new SecurityException("path escapes base directory");
        }
        return new FileInputStream(target.toFile());
    }
}
