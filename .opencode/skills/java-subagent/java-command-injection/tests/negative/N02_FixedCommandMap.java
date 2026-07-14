import java.io.IOException;
import java.util.Map;

public class N02_FixedCommandMap {
    private static final Map<String, String[]> JOBS = Map.of(
        "health", new String[] {"/usr/bin/true"},
        "version", new String[] {"/usr/bin/uname", "-a"}
    );

    public Process safe(String jobId) throws IOException {
        String[] argv = JOBS.get(jobId);
        if (argv == null) {
            throw new IllegalArgumentException("unknown job");
        }
        return new ProcessBuilder(argv).start();
    }
}
