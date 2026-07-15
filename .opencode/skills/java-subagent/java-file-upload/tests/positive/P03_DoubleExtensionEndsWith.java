import java.io.File;
import org.apache.commons.fileupload.FileItem;

public class P03_DoubleExtensionEndsWith {
    public File vulnerable(File uploadDir, FileItem item) throws Exception {
        String name = item.getName();
        String lower = name.toLowerCase();
        if (!(lower.endsWith(".png") || lower.endsWith(".jpg"))) {
            throw new IllegalArgumentException("only png/jpg");
        }
        File target = new File(uploadDir, new File(name).getName());
        item.write(target);
        return target;
    }
}
