// Pattern: classic string concatenation into XPath.compile/evaluate
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class BookXPathDao {
    private final Document catalog;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public BookXPathDao(Document catalog) {
        this.catalog = catalog;
    }

    public String findById(HttpServletRequest request) throws Exception {
        String bookId = request.getParameter("bookId");
        String expr = "//book[@id='" + bookId + "']/title/text()";
        return xpath.evaluate(expr, catalog);
    }
}
