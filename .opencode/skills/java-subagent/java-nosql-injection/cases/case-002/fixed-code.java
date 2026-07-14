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
    public List<Document> advanced(
            @RequestParam(required = false) Double maxPrice,
            @RequestParam(required = false) String category) {
        List<Bson> parts = new ArrayList<>();
        if (maxPrice != null) {
            parts.add(Filters.lte("price", maxPrice));
        }
        if (category != null) {
            parts.add(Filters.eq("category", category));
        }
        Bson filter = parts.isEmpty() ? new Document() : Filters.and(parts);
        return items.find(filter).into(new ArrayList<>());
    }
}
