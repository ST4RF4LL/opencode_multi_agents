import java.util.Random;

public class P04_InsecureRandomToken {
    public String vulnerableSessionToken() {
        Random r = new Random();
        return Long.toHexString(r.nextLong()) + Long.toHexString(r.nextLong());
    }
}
