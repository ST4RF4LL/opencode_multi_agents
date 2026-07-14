import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
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
        Object username = credentials.get("username");
        Object password = credentials.get("password");
        if (!(username instanceof String) || !(password instanceof String)) {
            throw new IllegalArgumentException("invalid credentials");
        }
        Bson query = Filters.and(
            Filters.eq("username", username),
            Filters.eq("password", password)
        );
        return users.find(query).first();
    }
}
