// Regression: predicate concat must remain a positive candidate
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class R01_PredicateConcat {
    public String mustDetect(Document doc, String id) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//item[@id='" + id + "']", doc);
    }
}
