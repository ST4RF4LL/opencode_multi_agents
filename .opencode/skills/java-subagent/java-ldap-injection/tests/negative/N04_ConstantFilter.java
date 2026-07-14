import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

/** Negative: fully constant filter — no user influence. */
public class N04_ConstantFilter {
    private final DirContext ctx;

    public N04_ConstantFilter(DirContext ctx) {
        this.ctx = ctx;
    }

    public void listActiveUsers() throws Exception {
        String filter = "(objectClass=inetOrgPerson)";
        ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
