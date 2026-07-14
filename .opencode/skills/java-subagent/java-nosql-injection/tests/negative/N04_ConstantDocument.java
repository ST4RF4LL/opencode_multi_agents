import com.mongodb.client.MongoCollection;
import org.bson.Document;

public class N04_ConstantDocument {
    public Document safe(MongoCollection<Document> users) {
        Document query = new Document("status", "active");
        return users.find(query).first();
    }
}
