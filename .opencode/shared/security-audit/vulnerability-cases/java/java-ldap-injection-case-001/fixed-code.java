import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.support.LdapEncoder;

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
        // Prefer filterArgs binding; if concat is required, encode values only.
        String filter = "(&(uid={0})(userPassword={1}))";
        Object[] filterArgs = new Object[] { username, password };
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results =
            ctx.search(searchBase, filter, filterArgs, controls);
        return results.hasMore();
    }

    // Alternative: encode then insert into fixed template
    public boolean authenticateEncoded(HttpServletRequest request) throws Exception {
        String username = LdapEncoder.filterEncode(request.getParameter("username"));
        String password = LdapEncoder.filterEncode(request.getParameter("password"));
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        SearchControls controls = new SearchControls();
        NamingEnumeration<SearchResult> results = ctx.search(searchBase, filter, controls);
        return results.hasMore();
    }
}
