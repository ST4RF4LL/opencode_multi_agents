import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class P02_XPathCompileConcat {
    public String vulnerable(Document doc, String name) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//users/user[@name='" + name + "']";
        XPathExpression compiled = xpath.compile(expr);
        return compiled.evaluate(doc);
    }
}
