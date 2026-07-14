import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.support.LdapEncoder;

/** Negative: values encoded with LdapEncoder.filterEncode before fixed template. */
public class N02_LdapEncoderFilter {
    private final DirContext ctx;

    public N02_LdapEncoderFilter(DirContext ctx) {
        this.ctx = ctx;
    }

    public void search(HttpServletRequest request) throws Exception {
        String uid = LdapEncoder.filterEncode(request.getParameter("uid"));
        String filter = "(uid=" + uid + ")";
        ctx.search("dc=example,dc=com", filter, new SearchControls());
    }
}
