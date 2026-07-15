import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;

public class N04_JaxbHardenedStaxReader {
    public Object safe(InputStream xml) throws Exception {
        XMLInputFactory inputFactory = XMLInputFactory.newFactory();
        inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = inputFactory.createXMLStreamReader(xml);
        try {
            JAXBContext context = JAXBContext.newInstance(Object.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return unmarshaller.unmarshal(reader);
        } finally {
            reader.close();
        }
    }
}
