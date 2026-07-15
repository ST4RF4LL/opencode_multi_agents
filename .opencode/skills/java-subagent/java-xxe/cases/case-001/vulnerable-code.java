// Pattern: DocumentBuilderFactory default + parse untrusted body
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImportController {
    private final XmlImportService importService;

    public ImportController(XmlImportService importService) {
        this.importService = importService;
    }

    @PostMapping(value = "/api/import", consumes = "application/xml")
    public String importXml(HttpServletRequest request) throws Exception {
        return importService.parse(request.getInputStream());
    }
}

class XmlImportService {
    public String parse(java.io.InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xml);
        return doc.getDocumentElement().getTextContent();
    }
}
