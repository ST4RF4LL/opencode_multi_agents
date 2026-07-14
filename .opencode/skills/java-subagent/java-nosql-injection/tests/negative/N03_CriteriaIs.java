import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import java.util.List;

public class N03_CriteriaIs {
    public List<?> safe(MongoTemplate template, String name) {
        Query q = new Query(Criteria.where("name").is(name));
        return template.find(q, Object.class);
    }
}
