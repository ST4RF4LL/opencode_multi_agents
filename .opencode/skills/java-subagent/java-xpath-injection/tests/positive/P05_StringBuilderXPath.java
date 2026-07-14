import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class P05_StringBuilderXPath {
    public String vulnerable(Document doc, String path, String id) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = new StringBuilder("//")
                .append(path)
                .append("[@id='")
                .append(id)
                .append("']")
                .toString();
        return xpath.compile(expr).evaluate(doc);
    }
}
