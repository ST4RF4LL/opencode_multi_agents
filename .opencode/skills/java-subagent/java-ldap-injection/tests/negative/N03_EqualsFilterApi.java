import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.web.bind.annotation.RequestParam;

/** Negative: Spring EqualsFilter API encodes assertion values. */
public class N03_EqualsFilterApi {
    private final LdapTemplate ldapTemplate;

    public N03_EqualsFilterApi(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public Object search(@RequestParam String uid) {
        EqualsFilter filter = new EqualsFilter("uid", uid);
        return ldapTemplate.search("ou=people,dc=example,dc=com", filter.encode(), (Object ctx) -> ctx);
    }
}
