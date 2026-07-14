import java.io.IOException;

public class N04_ConstantCommand {
    public Process safe() throws IOException {
        return new ProcessBuilder("uname", "-a").start();
    }
}
