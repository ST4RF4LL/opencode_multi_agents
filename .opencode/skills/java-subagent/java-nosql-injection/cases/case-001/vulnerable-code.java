// Pattern: JSON operator injection via request Map used as Mongo filter
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class AuthController {
    private final MongoCollection<Document> users;

    public AuthController(MongoDatabase db) {
        this.users = db.getCollection("users");
    }

    @PostMapping("/api/login")
    public Document login(@RequestBody Map<String, Object> credentials) {
        // Attacker can send {"username":"admin","password":{"$ne":""}}
        Document query = new Document(credentials);
        return users.find(query).first();
    }
}
