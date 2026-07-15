import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class N03_ConstantFixtureCopy {
    public Path safe(Path privateDir) throws Exception {
        Path target = privateDir.resolve("default-avatar.png");
        try (InputStream in = N03_ConstantFixtureCopy.class.getResourceAsStream("/fixtures/default-avatar.png")) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }
}
