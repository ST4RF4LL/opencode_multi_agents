import javax.persistence.EntityManager;
import javax.persistence.Query;

/** Negative: constant JPQL with named setParameter (OWASP Java CS JPA). */
public class N06_JpaJpqlNamedParam {
    public Query safe(EntityManager em, String colorName) {
        Query q = em.createQuery(
            "select c from Color c where c.friendlyName = :colorName");
        q.setParameter("colorName", colorName);
        return q;
    }
}
