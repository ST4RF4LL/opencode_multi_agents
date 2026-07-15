// Pattern: save any extension under webapp/ with original filename
import java.io.File;
import org.springframework.web.multipart.MultipartFile;

public class StorageService {
    private final File webappUploadDir;

    public StorageService(File webappUploadDir) {
        this.webappUploadDir = webappUploadDir;
    }

    public File storeAny(MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        File target = new File(webappUploadDir, original);
        file.transferTo(target);
        return target;
    }
}
