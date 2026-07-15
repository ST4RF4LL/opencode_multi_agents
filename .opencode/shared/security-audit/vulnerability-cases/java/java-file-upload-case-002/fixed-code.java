import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

public class AvatarService {
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg", "gif");
    private final Path uploadDir;

    public AvatarService(Path uploadDir) {
        this.uploadDir = uploadDir;
    }

    public Path saveIfImage(MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        if (original == null) {
            throw new SecurityException("missing filename");
        }
        String base = Path.of(original).getFileName().toString();
        int dot = base.lastIndexOf('.');
        if (dot < 0) {
            throw new SecurityException("missing extension");
        }
        String ext = base.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("extension not allowed");
        }
        try (InputStream in = file.getInputStream()) {
            if (ImageIO.read(in) == null) {
                throw new SecurityException("not a valid image");
            }
        }
        Path target = uploadDir.resolve(UUID.randomUUID() + "." + ext);
        try (InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
