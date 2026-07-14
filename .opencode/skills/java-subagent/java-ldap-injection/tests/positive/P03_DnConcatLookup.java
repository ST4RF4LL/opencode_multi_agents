import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

/** Positive: DN injection via concat into getAttributes/lookup. */
public class P03_DnConcatLookup {
    private final DirContext ctx;
    private final String baseDn = "ou=people,dc=example,dc=com";

    public P03_DnConcatLookup(DirContext ctx) {
        this.ctx = ctx;
    }

    public Attributes getUser(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        String dn = "uid=" + userId + "," + baseDn;
        return ctx.getAttributes(dn);
    }
}
