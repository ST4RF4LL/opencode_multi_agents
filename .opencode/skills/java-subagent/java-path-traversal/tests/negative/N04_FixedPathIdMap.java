import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class N04_FixedPathIdMap {
    private static final Map<String, String> FILES = Map.of(
        "a", "docs/a.pdf",
        "b", "docs/b.pdf"
    );

    public byte[] safe(Path baseDir, String fileId) throws Exception {
        String relative = FILES.get(fileId);
        if (relative == null) {
            throw new IllegalArgumentException("unknown file id");
        }
        Path base = baseDir.toAbsolutePath().normalize();
        Path target = base.resolve(relative).normalize();
        if (!target.startsWith(base)) {
            throw new SecurityException("path escapes base directory");
        }
        return Files.readAllBytes(target);
    }
}
