import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImportController {

    private static final ObjectInputFilter FILTER =
        ObjectInputFilter.Config.createFilter("com.example.dto.*;!*");

    @PostMapping("/api/import")
    public Object importBlob(HttpServletRequest request) throws Exception {
        InputStream in = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(FILTER);
        return ois.readObject();
    }
}
