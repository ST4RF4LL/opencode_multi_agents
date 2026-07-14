import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.NamingEnumeration;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.ldap.support.LdapNameBuilder;

public class LdapUserRepository {
    private final DirContext ctx;
    private final String baseDn;

    public LdapUserRepository(DirContext ctx, String baseDn) {
        this.ctx = ctx;
        this.baseDn = baseDn;
    }

    public Attributes lookupByUidEncoded(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        String dn = LdapNameBuilder.newInstance(baseDn)
            .add("uid", LdapEncoder.nameEncode(userId))
            .build()
            .toString();
        return ctx.getAttributes(dn);
    }

    // Prefer constant base + parameterized/encoded filter search
    public Attributes lookupByUidSearch(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        String filter = "(uid={0})";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results =
            ctx.search(baseDn, filter, new Object[] { userId }, controls);
        if (results.hasMore()) {
            return results.next().getAttributes();
        }
        return null;
    }
}
