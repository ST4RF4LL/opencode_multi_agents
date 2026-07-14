import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import java.util.Set;

public class N05_FieldAllowlist {
    private static final Set<String> ALLOWED = Set.of("name", "email", "createdAt");

    public Document safe(MongoCollection<Document> users, String field, String value) {
        String f = ALLOWED.contains(field) ? field : "name";
        Bson query = Filters.eq(f, value);
        return users.find(query).first();
    }
}
