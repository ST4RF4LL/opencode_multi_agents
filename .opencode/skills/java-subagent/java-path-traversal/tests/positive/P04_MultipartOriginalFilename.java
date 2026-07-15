import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.web.multipart.MultipartFile;

public class P04_MultipartOriginalFilename {
    public Path vulnerable(Path uploadDir, MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        Path target = uploadDir.resolve(original);
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
