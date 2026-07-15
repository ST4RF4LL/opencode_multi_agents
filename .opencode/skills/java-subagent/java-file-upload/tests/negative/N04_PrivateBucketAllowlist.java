import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class N04_PrivateBucketAllowlist {
    private static final Set<String> ALLOWED = Set.of("pdf", "png");

    public String safe(ObjectStorage client, MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        String base = original == null ? "" : original.replace("\\", "/");
        int slash = base.lastIndexOf('/');
        if (slash >= 0) {
            base = base.substring(slash + 1);
        }
        int dot = base.lastIndexOf('.');
        if (dot < 0) {
            throw new SecurityException("missing extension");
        }
        String ext = base.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(ext)) {
            throw new SecurityException("not allowed");
        }
        String key = "private/" + UUID.randomUUID() + "." + ext;
        client.putPrivate(key, file.getBytes());
        return key;
    }

    interface ObjectStorage {
        void putPrivate(String key, byte[] data) throws Exception;
    }
}
