// Pattern: wrong encoding context — forHtml inside JavaScript string
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class NotifyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String msg = request.getParameter("msg");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        // WRONG context: HTML encoder used for JS string literal
        out.print("<script>showNotify('" + Encode.forHtml(msg) + "');</script>");
    }
}
