import java.io.IOException;

public class P05_ProcessBuilderCmdC {
    public Process vulnerable(String arg) throws IOException {
        return new ProcessBuilder("cmd.exe", "/c", "dir " + arg).start();
    }
}
