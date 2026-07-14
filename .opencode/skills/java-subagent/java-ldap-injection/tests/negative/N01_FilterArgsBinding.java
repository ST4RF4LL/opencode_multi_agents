import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

/** Negative: constant filter template with filterArgs — should NOT be a finding. */
public class N01_FilterArgsBinding {
    private final DirContext ctx;

    public N01_FilterArgsBinding(DirContext ctx) {
        this.ctx = ctx;
    }

    public boolean login(HttpServletRequest request) throws Exception {
        String user = request.getParameter("username");
        String pass = request.getParameter("password");
        String filter = "(&(uid={0})(userPassword={1}))";
        Object[] args = new Object[] { user, pass };
        SearchControls sc = new SearchControls();
        NamingEnumeration<SearchResult> res =
            ctx.search("ou=people,dc=example,dc=com", filter, args, sc);
        return res.hasMore();
    }
}
