// Regression: Document.parse must remain a high-priority sink candidate
import org.bson.Document;

public class R01_DocumentParse {
    public Document mustDetect(String userJson) {
        return Document.parse(userJson);
    }
}
