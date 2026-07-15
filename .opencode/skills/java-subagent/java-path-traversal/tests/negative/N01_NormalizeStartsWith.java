import java.nio.file.Files;
import java.nio.file.Path;

public class N01_NormalizeStartsWith {
    public byte[] safe(Path baseDir, String userPath) throws Exception {
        Path base = baseDir.toAbsolutePath().normalize();
        Path target = base.resolve(userPath).normalize();
        if (!target.startsWith(base)) {
            throw new SecurityException("path escapes base directory");
        }
        return Files.readAllBytes(target);
    }
}
