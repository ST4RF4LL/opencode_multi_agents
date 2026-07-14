import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;

public class N02_FiltersAndScalars {
    public Document safe(MongoCollection<Document> users, String username, String password) {
        return users.find(Filters.and(
            Filters.eq("username", username),
            Filters.eq("password", password)
        )).first();
    }
}
