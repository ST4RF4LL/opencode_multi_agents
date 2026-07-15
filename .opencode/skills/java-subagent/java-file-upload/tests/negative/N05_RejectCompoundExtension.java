import java.io.File;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.apache.commons.fileupload.FileItem;

public class N05_RejectCompoundExtension {
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg");

    public File safe(File uploadDir, FileItem item) throws Exception {
        String name = item.getName();
        if (name == null) {
            throw new SecurityException("missing name");
        }
        String base = new File(name).getName();
        int first = base.indexOf('.');
        int last = base.lastIndexOf('.');
        if (last < 0 || first != last) {
            throw new SecurityException("compound extension rejected");
        }
        String ext = base.substring(last + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("not allowed");
        }
        File target = new File(uploadDir, UUID.randomUUID() + "." + ext);
        item.write(target);
        return target;
    }
}
