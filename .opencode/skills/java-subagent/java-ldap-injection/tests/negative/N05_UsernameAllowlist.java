import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;

/** Negative: username mapped through allowlist to constant filter fragment. */
public class N05_UsernameAllowlist {
    private final DirContext ctx;
    private static final Set<String> ALLOWED = Set.of("alice", "bob", "service-reader");
    private static final Map<String, String> FILTERS = Map.of(
        "alice", "(uid=alice)",
        "bob", "(uid=bob)",
        "service-reader", "(uid=service-reader)"
    );

    public N05_UsernameAllowlist(DirContext ctx) {
        this.ctx = ctx;
    }

    public void search(HttpServletRequest request) throws Exception {
        String user = request.getParameter("username");
        if (!ALLOWED.contains(user)) {
            throw new IllegalArgumentException("not allowed");
        }
        String filter = FILTERS.get(user);
        ctx.search("dc=example,dc=com", filter, new SearchControls());
    }
}
