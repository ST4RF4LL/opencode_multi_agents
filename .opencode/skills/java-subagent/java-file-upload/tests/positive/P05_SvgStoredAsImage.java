import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.web.multipart.MultipartFile;

public class P05_SvgStoredAsImage {
    public Path vulnerable(Path publicDir, MultipartFile file) throws Exception {
        String name = file.getOriginalFilename();
        String ct = file.getContentType();
        if (name != null && (name.endsWith(".svg") || "image/svg+xml".equals(ct))) {
            Path target = publicDir.resolve(name);
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        }
        throw new IllegalArgumentException("svg only demo");
    }
}
