import java.io.IOException;

public class P02_ProcessBuilderShell {
    public Process vulnerable(String script) throws IOException {
        return new ProcessBuilder("/bin/sh", "-c", script).start();
    }
}
