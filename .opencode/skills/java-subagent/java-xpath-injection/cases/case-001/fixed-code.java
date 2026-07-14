import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

public class BookXPathDao {
    private final Document catalog;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public BookXPathDao(Document catalog) {
        this.catalog = catalog;
    }

    public String findById(HttpServletRequest request) throws Exception {
        String bookId = request.getParameter("bookId");
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            @Override
            public Object resolveVariable(QName variableName) {
                if ("bookId".equals(variableName.getLocalPart())) {
                    return bookId;
                }
                return null;
            }
        });
        // OWASP Java Security CS: parameterized XPath with $var
        return xpath.evaluate("//book[@id=$bookId]/title/text()", catalog);
    }
}
