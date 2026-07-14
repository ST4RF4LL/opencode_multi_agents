import java.io.IOException;

public class P03_RuntimeExecShellArray {
    public Process vulnerable(String userCmd) throws IOException {
        return Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", userCmd});
    }
}
