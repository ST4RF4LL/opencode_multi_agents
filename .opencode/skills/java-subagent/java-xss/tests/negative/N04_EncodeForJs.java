import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class N04_EncodeForJs {
    public void safe(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String msg = request.getParameter("msg");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.print("<script>var m = '" + Encode.forJavaScript(msg) + "';</script>");
    }
}
