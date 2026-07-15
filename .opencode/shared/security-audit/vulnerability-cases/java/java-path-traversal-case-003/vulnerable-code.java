// Pattern: multipart getOriginalFilename used as storage path
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.web.multipart.MultipartFile;

public class StorageService {
    private final Path uploadDir;

    public StorageService(Path uploadDir) {
        this.uploadDir = uploadDir;
    }

    public Path store(MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        Path target = uploadDir.resolve(original);
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
