import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class P04_LoginBooleanConcat {
    public boolean vulnerable(Document users, String username, String password) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//user[name/text()='" + username
                + "' and password/text()='" + password + "']";
        String result = xpath.evaluate(expr, users);
        return result != null && !result.isEmpty();
    }
}
