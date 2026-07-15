import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

public class N02_ImageDecodeReencode {
    public Path safe(Path privateDir, MultipartFile file) throws Exception {
        try (InputStream in = file.getInputStream()) {
            BufferedImage img = ImageIO.read(in);
            if (img == null) {
                throw new SecurityException("not an image");
            }
            Path target = privateDir.resolve(UUID.randomUUID() + ".png");
            ImageIO.write(img, "png", target.toFile());
            return target;
        }
    }
}
