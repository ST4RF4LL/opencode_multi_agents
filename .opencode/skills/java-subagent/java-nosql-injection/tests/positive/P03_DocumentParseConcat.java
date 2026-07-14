import com.mongodb.client.MongoCollection;
import org.bson.Document;

public class P03_DocumentParseConcat {
    public Document vulnerable(MongoCollection<Document> users, String username) {
        String json = "{ \"username\": \"" + username + "\" }";
        Document query = Document.parse(json);
        return users.find(query).first();
    }
}
