import java.io.File;
import org.springframework.web.multipart.MultipartFile;

/** Regression: must continue to flag unrestricted original-name store under webapp. */
public class R01_UnrestrictedExtensionWebapp {
    public File vulnerable(File webappUploadDir, MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        File target = new File(webappUploadDir, original);
        file.transferTo(target);
        return target;
    }
}
