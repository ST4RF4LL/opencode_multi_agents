// Pattern: Runtime.exec with string concatenation (classic CMDi)
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class NetService {
    public Process pingHost(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        String cmd = "ping -c 1 " + host;
        return Runtime.getRuntime().exec(cmd);
    }
}
