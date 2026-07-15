// Pattern: Content-Type image/* only then store as-is
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.web.multipart.MultipartFile;

public class AvatarService {
    private final Path uploadDir;

    public AvatarService(Path uploadDir) {
        this.uploadDir = uploadDir;
    }

    public Path saveIfImage(MultipartFile file) throws Exception {
        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            throw new IllegalArgumentException("only images allowed");
        }
        String original = file.getOriginalFilename();
        Path target = uploadDir.resolve(original);
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
