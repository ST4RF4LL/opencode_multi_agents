import java.io.File;
import javax.servlet.ServletContext;
import javax.servlet.http.Part;

public class P04_ServletPartWebroot {
    public void vulnerable(ServletContext ctx, Part part) throws Exception {
        String real = ctx.getRealPath("/uploads");
        String submitted = part.getSubmittedFileName();
        part.write(real + File.separator + submitted);
    }
}
