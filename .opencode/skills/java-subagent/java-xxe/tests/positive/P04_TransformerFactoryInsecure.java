import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.io.OutputStream;

public class P04_TransformerFactoryInsecure {
    public void vulnerable(InputStream xml, OutputStream out) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.transform(new StreamSource(xml), new StreamResult(out));
    }
}
