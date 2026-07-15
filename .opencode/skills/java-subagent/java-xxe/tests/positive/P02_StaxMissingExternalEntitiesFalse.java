import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;

public class P02_StaxMissingExternalEntitiesFalse {
    public XMLStreamReader vulnerable(InputStream xml) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        return factory.createXMLStreamReader(xml);
    }
}
