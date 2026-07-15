import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class R01_DocumentBuilderDefaultParse {
    public Document mustDetect(String xmlBody) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlBody.getBytes("UTF-8")));
    }
}
