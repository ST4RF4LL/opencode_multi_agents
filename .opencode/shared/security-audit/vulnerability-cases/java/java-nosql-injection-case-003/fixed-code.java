import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
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
        return users.find(Filters.eq("username", username)).first();
    }
}
