// Pattern: string concatenation into query JSON then Document.parse
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final MongoCollection<Document> users;

    public UserController(MongoDatabase db) {
        this.users = db.getCollection("users");
    }

    @GetMapping("/api/users/by-name")
    public Document find(@RequestParam String username) {
        String json = "{ \"username\": \"" + username + "\" }";
        Document query = Document.parse(json);
        return users.find(query).first();
    }
}
