import java.io.IOException;
import java.net.InetAddress;
import javax.servlet.http.HttpServletRequest;

public class NetService {
    public boolean pingHost(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        // Prefer pure Java API instead of shelling out to ping
        InetAddress address = InetAddress.getByName(host);
        return address.isReachable(3000);
    }

    // Alternative if a process is required: list form, fixed binary, single validated arg
    public Process pingHostProcess(String host) throws IOException {
        if (!host.matches("^[A-Za-z0-9._-]+$")) {
            throw new IllegalArgumentException("invalid host");
        }
        return new ProcessBuilder("ping", "-c", "1", host).start();
    }
}
