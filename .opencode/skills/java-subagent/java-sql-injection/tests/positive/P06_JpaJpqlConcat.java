import javax.persistence.EntityManager;
import javax.persistence.Query;

/** Positive: JPQL string concat into createQuery (not createNativeQuery). */
public class P06_JpaJpqlConcat {
    public Query vulnerable(EntityManager em, String colorName) {
        String jpql = "select c from Color c where c.friendlyName = '" + colorName + "'";
        return em.createQuery(jpql);
    }
}
