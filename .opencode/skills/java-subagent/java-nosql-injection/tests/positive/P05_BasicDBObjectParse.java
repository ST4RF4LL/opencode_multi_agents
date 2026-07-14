import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import org.bson.Document;

public class P05_BasicDBObjectParse {
    public Document vulnerable(MongoCollection<Document> users, String raw) {
        BasicDBObject query = BasicDBObject.parse(raw);
        return users.find(new Document(query)).first();
    }
}
