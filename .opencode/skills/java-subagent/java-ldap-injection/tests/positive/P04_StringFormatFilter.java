import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

/** Positive: String.format builds filter from user input. */
public class P04_StringFormatFilter {
    private final DirContext ctx;

    public P04_StringFormatFilter(DirContext ctx) {
        this.ctx = ctx;
    }

    public void find(HttpServletRequest request) throws Exception {
        String uid = request.getParameter("uid");
        String filter = String.format("(uid=%s)", uid);
        ctx.search("dc=example,dc=com", filter, new SearchControls());
    }
}
