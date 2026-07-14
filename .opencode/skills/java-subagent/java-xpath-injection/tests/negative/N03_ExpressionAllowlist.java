import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import java.util.Map;

public class N03_ExpressionAllowlist {
    private static final Map<String, String> ALLOWED = Map.of(
            "title", "//book/title/text()",
            "author", "//book/author/text()"
    );

    public String safe(Document doc, String field) throws Exception {
        String expr = ALLOWED.getOrDefault(field, "//book/title/text()");
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(expr, doc);
    }
}
