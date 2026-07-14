import java.io.IOException;

public class N01_ProcessBuilderListSafe {
    public Process safe(String host) throws IOException {
        if (!host.matches("^[A-Za-z0-9._-]+$")) {
            throw new IllegalArgumentException("invalid host");
        }
        // Fixed binary, list form, no shell; host is single validated argv token
        return new ProcessBuilder("ping", "-c", "1", host).start();
    }
}
