// Pattern: double extension / content mismatch bypass via weak endsWith
import java.io.File;
import org.apache.commons.fileupload.FileItem;

public class UploadHelper {
    private final File uploadDir;

    public UploadHelper(File uploadDir) {
        this.uploadDir = uploadDir;
    }

    public File acceptImageName(FileItem item) throws Exception {
        String name = item.getName();
        if (name == null) {
            throw new IllegalArgumentException("missing name");
        }
        String lower = name.toLowerCase();
        if (!(lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg"))) {
            throw new IllegalArgumentException("only png/jpg");
        }
        // FAKE: client may send photo.jpg.jsp if check order differs, or
        // content/type mismatch when only extension suffix is checked loosely.
        // Weak pattern also accepts "evil.jsp.png" then serves by mapped type.
        File target = new File(uploadDir, new File(name).getName());
        item.write(target);
        return target;
    }
}
