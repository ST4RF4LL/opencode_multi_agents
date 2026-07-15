import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

@RestController
public class UploadController {
    private final StaxXmlProcessor processor;

    public UploadController(StaxXmlProcessor processor) {
        this.processor = processor;
    }

    @PostMapping("/api/upload-xml")
    public String upload(@RequestPart("file") MultipartFile file) throws Exception {
        return processor.process(file.getInputStream());
    }
}

class StaxXmlProcessor {
    public String process(java.io.InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(in);
        StringBuilder sb = new StringBuilder();
        while (reader.hasNext()) {
            reader.next();
            if (reader.isStartElement()) {
                sb.append(reader.getLocalName()).append(';');
            }
        }
        reader.close();
        return sb.toString();
    }
}
