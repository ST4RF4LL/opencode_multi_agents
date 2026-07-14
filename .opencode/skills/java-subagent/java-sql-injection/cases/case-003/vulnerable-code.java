// Pattern: JPA createNativeQuery with string concatenation
import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class AccountController {
    private final EntityManager em;

    public AccountController(EntityManager em) {
        this.em = em;
    }

    @GetMapping("/api/accounts/search")
    public List<?> search(@RequestParam String email) {
        String sql = "SELECT * FROM accounts WHERE email = '" + email + "'";
        Query q = em.createNativeQuery(sql);
        return q.getResultList();
    }
}
