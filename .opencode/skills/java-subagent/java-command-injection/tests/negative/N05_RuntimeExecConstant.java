import java.io.IOException;

public class N05_RuntimeExecConstant {
    public Process safe() throws IOException {
        return Runtime.getRuntime().exec(new String[] {"echo", "ok"});
    }
}
