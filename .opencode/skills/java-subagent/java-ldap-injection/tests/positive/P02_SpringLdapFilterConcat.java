import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Positive: Spring LdapTemplate with concatenated filter. */
@RestController
public class P02_SpringLdapFilterConcat {
    private final LdapTemplate ldapTemplate;

    public P02_SpringLdapFilterConcat(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    @GetMapping("/search")
    public Object search(@RequestParam String cn) {
        String filter = "(cn=" + cn + ")";
        return ldapTemplate.search("ou=people,dc=example,dc=com", filter, (Object ctx) -> ctx);
    }
}
