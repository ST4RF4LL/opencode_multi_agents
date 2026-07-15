import java.io.File;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class StorageService {
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg", "gif", "pdf");
    private final File privateUploadDir;

    public StorageService(File privateUploadDir) {
        this.privateUploadDir = privateUploadDir;
    }

    public File storeAny(MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        if (original == null || original.isBlank()) {
            throw new SecurityException("missing filename");
        }
        String base = new File(original).getName();
        int dot = base.lastIndexOf('.');
        if (dot < 0 || base.indexOf('.') != dot) {
            throw new SecurityException("invalid or compound extension");
        }
        String ext = base.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("extension not allowed");
        }
        File target = new File(privateUploadDir, UUID.randomUUID() + "." + ext);
        file.transferTo(target);
        return target;
    }
}
