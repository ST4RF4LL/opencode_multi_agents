import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Set;

public class N02_BasenameAllowlist {
    private static final Set<String> ALLOWED = Set.of("report.pdf", "readme.txt", "guide.html");

    public InputStream safe(File baseDir, String filename) throws Exception {
        if (!ALLOWED.contains(filename)) {
            throw new IllegalArgumentException("filename not allowed");
        }
        if (filename.contains("/") || filename.contains("\\") || filename.contains("..")) {
            throw new IllegalArgumentException("invalid filename");
        }
        File target = new File(baseDir, filename);
        return new FileInputStream(target);
    }
}
