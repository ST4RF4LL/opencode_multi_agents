import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

/** Positive: filter concat login — should be flagged as LDAP injection candidate. */
public class P01_FilterConcatLogin {
    private final DirContext ctx;

    public P01_FilterConcatLogin(DirContext ctx) {
        this.ctx = ctx;
    }

    public boolean login(HttpServletRequest request) throws Exception {
        String user = request.getParameter("username");
        String pass = request.getParameter("password");
        String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
        SearchControls sc = new SearchControls();
        NamingEnumeration<SearchResult> res = ctx.search("ou=people,dc=example,dc=com", filter, sc);
        return res.hasMore();
    }
}
