import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;

public class N01_FiltersEq {
    public Document safe(MongoCollection<Document> users, String username) {
        return users.find(Filters.eq("username", username)).first();
    }
}
