import javax.persistence.EntityManager;
import javax.persistence.Query;

public class P04_JpaNativeConcat {
    public Query vulnerable(EntityManager em, String email) {
        String sql = "SELECT * FROM accounts WHERE email = '" + email + "'";
        return em.createNativeQuery(sql);
    }
}
