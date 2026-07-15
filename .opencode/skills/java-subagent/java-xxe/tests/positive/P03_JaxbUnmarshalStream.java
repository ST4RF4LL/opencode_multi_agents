import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import java.io.InputStream;

public class P03_JaxbUnmarshalStream {
    public Object vulnerable(InputStream xml) throws Exception {
        JAXBContext context = JAXBContext.newInstance(Object.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return unmarshaller.unmarshal(xml);
    }
}
