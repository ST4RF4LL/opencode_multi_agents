// Pattern: DN injection via string concat into lookup/search base
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

public class LdapUserRepository {
    private final DirContext ctx;
    private final String baseDn;

    public LdapUserRepository(DirContext ctx, String baseDn) {
        this.ctx = ctx;
        this.baseDn = baseDn;
    }

    public Attributes lookupByUid(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        // User controls RDN; metacharacters can alter DN path
        String dn = "uid=" + userId + "," + baseDn;
        return ctx.getAttributes(dn);
    }
}
