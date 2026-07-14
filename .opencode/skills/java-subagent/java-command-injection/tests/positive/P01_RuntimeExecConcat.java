import java.io.IOException;

public class P01_RuntimeExecConcat {
    public Process vulnerable(String host) throws IOException {
        String cmd = "ping -c 1 " + host;
        return Runtime.getRuntime().exec(cmd);
    }
}
