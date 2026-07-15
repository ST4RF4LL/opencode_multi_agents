import java.nio.file.Files;
import java.nio.file.Path;

public class P02_PathResolveRead {
    public byte[] vulnerable(Path baseDir, String userPath) throws Exception {
        Path target = baseDir.resolve(userPath);
        return Files.readAllBytes(target);
    }
}
