import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class N02_ConstantXPath {
    public String safe(Document doc) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//book[@id='fixed']/title/text()", doc);
    }
}
