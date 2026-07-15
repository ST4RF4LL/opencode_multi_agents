import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.web.multipart.MultipartFile;

public class P02_MimeOnlyValidation {
    public Path vulnerable(Path uploadDir, MultipartFile file) throws Exception {
        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            throw new IllegalArgumentException("only images");
        }
        Path target = uploadDir.resolve(file.getOriginalFilename());
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
