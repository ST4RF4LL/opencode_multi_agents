import javax.persistence.EntityManager;
import javax.persistence.Query;

public class N04_JpaNamedParam {
    public Query safe(EntityManager em, String email) {
        Query q = em.createNativeQuery("SELECT * FROM accounts WHERE email = :email");
        q.setParameter("email", email);
        return q;
    }
}
