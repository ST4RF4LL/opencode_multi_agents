import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class ColorController {
    private final EntityManager em;

    public ColorController(EntityManager em) {
        this.em = em;
    }

    @GetMapping("/api/colors")
    public List<?> findByName(@RequestParam String colorName) {
        Query q = em.createQuery(
            "select c from Color c where c.friendlyName = :colorName");
        q.setParameter("colorName", colorName);
        return q.getResultList();
    }
}
