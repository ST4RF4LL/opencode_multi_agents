import java.io.File;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.apache.commons.fileupload.FileItem;

public class UploadHelper {
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg");
    private final File uploadDir;

    public UploadHelper(File uploadDir) {
        this.uploadDir = uploadDir;
    }

    public File acceptImageName(FileItem item) throws Exception {
        String name = item.getName();
        if (name == null) {
            throw new SecurityException("missing name");
        }
        String base = new File(name).getName();
        int firstDot = base.indexOf('.');
        int lastDot = base.lastIndexOf('.');
        if (lastDot < 0 || firstDot != lastDot) {
            throw new SecurityException("compound or missing extension rejected");
        }
        String ext = base.substring(lastDot + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("extension not allowed");
        }
        File target = new File(uploadDir, UUID.randomUUID() + "." + ext);
        item.write(target);
        return target;
    }
}
