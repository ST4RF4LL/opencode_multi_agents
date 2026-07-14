import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

public class N04_CompileBoundVariable {
    public String safe(Document doc, String userId) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(variableName -> {
            if ("userId".equals(variableName.getLocalPart())) {
                return userId;
            }
            return null;
        });
        XPathExpression compiled = xpath.compile("//user[@id=$userId]");
        return compiled.evaluate(doc);
    }
}
