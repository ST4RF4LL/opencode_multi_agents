import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class N05_ConstantClasspathXml {
    public Document safe() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream xml = N05_ConstantClasspathXml.class.getResourceAsStream("/config/app-static.xml");
        return builder.parse(xml);
    }
}
