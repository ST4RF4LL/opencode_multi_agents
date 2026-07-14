import com.mongodb.client.MongoCollection;
import org.bson.Document;
import java.util.Map;

public class P01_JsonOperatorInject {
    public Document vulnerable(MongoCollection<Document> users, Map<String, Object> body) {
        Document query = new Document(body);
        return users.find(query).first();
    }
}
