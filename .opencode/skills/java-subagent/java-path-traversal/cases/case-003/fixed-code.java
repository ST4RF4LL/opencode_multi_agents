import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class StorageService {
    private final Path uploadDir;

    public StorageService(Path uploadDir) {
        this.uploadDir = uploadDir.toAbsolutePath().normalize();
    }

    public Path store(MultipartFile file) throws Exception {
        // Server-generated name; original filename is metadata only (not path)
        String safeName = UUID.randomUUID().toString();
        Path target = uploadDir.resolve(safeName).normalize();
        if (!target.startsWith(uploadDir)) {
            throw new SecurityException("path escapes upload directory");
        }
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
