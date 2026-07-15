import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;
import java.io.InputStream;

public class P05_SaxParserDefault {
    public void vulnerable(InputStream xml) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(xml, new DefaultHandler());
    }
}
