import java.io.File;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class N01_ExtensionAllowlistUuid {
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg", "gif");

    public File safe(File privateDir, MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        if (original == null) {
            throw new SecurityException("missing filename");
        }
        String base = new File(original).getName();
        int dot = base.lastIndexOf('.');
        if (dot < 0 || base.indexOf('.') != dot) {
            throw new SecurityException("invalid extension");
        }
        String ext = base.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("not allowed");
        }
        File target = new File(privateDir, UUID.randomUUID() + "." + ext);
        file.transferTo(target);
        return target;
    }
}
