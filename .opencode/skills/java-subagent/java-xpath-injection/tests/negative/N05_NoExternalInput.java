import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class N05_NoExternalInput {
    private static final String QUERY = "//config/version/text()";

    public String safe(Document doc) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.compile(QUERY).evaluate(doc);
    }
}
