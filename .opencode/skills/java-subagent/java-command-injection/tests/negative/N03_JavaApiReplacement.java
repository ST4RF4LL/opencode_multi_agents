import java.io.IOException;
import java.net.InetAddress;

public class N03_JavaApiReplacement {
    public boolean safe(String host) throws IOException {
        return InetAddress.getByName(host).isReachable(2000);
    }
}
