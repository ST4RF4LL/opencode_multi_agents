import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class N05_no_external_input {
    public void safe(HttpServletResponse response, boolean useDocs) throws IOException {
        String target = useDocs ? "/app/docs" : "/app/home";
        response.sendRedirect(target);
    }
}
