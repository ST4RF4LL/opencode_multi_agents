import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

public class N01_VariableResolver {
    public String safe(Document doc, String bookId) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            @Override
            public Object resolveVariable(QName variableName) {
                if ("bookId".equals(variableName.getLocalPart())) {
                    return bookId;
                }
                return null;
            }
        });
        return xpath.evaluate("//book[@id=$bookId]/title/text()", doc);
    }
}
