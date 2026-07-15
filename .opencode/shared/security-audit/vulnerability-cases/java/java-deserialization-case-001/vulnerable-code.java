// Pattern: ObjectInputStream on request body bytes
import java.io.InputStream;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImportController {

    @PostMapping("/api/import")
    public Object importBlob(HttpServletRequest request) throws Exception {
        InputStream in = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
