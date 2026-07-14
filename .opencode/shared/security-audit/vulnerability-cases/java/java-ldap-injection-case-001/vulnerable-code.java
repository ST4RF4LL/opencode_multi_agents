// Pattern: classic JNDI filter string concat for LDAP login/search (auth bypass surface)
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class LdapAuthService {
    private final DirContext ctx;
    private final String searchBase;

    public LdapAuthService(DirContext ctx, String searchBase) {
        this.ctx = ctx;
        this.searchBase = searchBase;
    }

    public boolean authenticate(HttpServletRequest request) throws Exception {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(searchBase, filter, controls);
        return results.hasMore();
    }
}
