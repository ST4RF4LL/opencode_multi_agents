// Pattern: $where / Filters.where with user-controlled expression
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.ArrayList;
import java.util.List;

@RestController
public class SearchController {
    private final MongoCollection<Document> items;

    public SearchController(MongoDatabase db) {
        this.items = db.getCollection("items");
    }

    @GetMapping("/api/items/search")
    public List<Document> advanced(@RequestParam String expr) {
        // Attacker controls server-side JS: expr = "this.price < 1 || true"
        Bson filter = Filters.where(expr);
        return items.find(filter).into(new ArrayList<>());
    }
}
