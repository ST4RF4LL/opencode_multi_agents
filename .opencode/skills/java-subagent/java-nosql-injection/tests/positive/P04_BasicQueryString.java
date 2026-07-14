import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import java.util.List;

public class P04_BasicQueryString {
    public List<?> vulnerable(MongoTemplate template, String filterJson) {
        BasicQuery query = new BasicQuery(filterJson);
        return template.find(query, Object.class);
    }
}
