import java.io.IOException;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;

public class P04_CommonsExecParse {
    public int vulnerable(String cmd) throws IOException {
        CommandLine cl = CommandLine.parse(cmd);
        return new DefaultExecutor().execute(cl);
    }
}
