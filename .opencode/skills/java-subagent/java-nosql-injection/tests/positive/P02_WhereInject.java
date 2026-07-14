import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import java.util.ArrayList;
import java.util.List;

public class P02_WhereInject {
    public List<Document> vulnerable(MongoCollection<Document> col, String expr) {
        return col.find(Filters.where(expr)).into(new ArrayList<>());
    }
}
