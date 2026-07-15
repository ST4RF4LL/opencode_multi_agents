import java.io.File;
import org.springframework.web.multipart.MultipartFile;

public class P01_UnrestrictedExtensionWebapp {
    public File vulnerable(File webappUploadDir, MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        File target = new File(webappUploadDir, original);
        file.transferTo(target);
        return target;
    }
}
