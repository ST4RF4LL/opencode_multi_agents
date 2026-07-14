import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class P01_XPathConcat {
    public String vulnerable(Document doc, String bookId) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//book[@id='" + bookId + "']/title/text()";
        return xpath.evaluate(expr, doc);
    }
}
