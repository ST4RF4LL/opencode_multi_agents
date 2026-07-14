import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class P03_XPathFormat {
    public String vulnerable(Document doc, String attr, String value) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = String.format("//item[@%s='%s']", attr, value);
        return xpath.evaluate(expr, doc);
    }
}
