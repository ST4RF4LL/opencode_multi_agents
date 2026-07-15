import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

@RestController
public class OrderController {
    private final JaxbOrderService orderService;

    public OrderController(JaxbOrderService orderService) {
        this.orderService = orderService;
    }

    @PostMapping(value = "/api/orders", consumes = "application/xml")
    public Order submit(HttpServletRequest request) throws Exception {
        return orderService.unmarshal(request.getInputStream());
    }
}

class JaxbOrderService {
    private final JAXBContext context;
    private final XMLInputFactory inputFactory;

    JaxbOrderService() throws Exception {
        this.context = JAXBContext.newInstance(Order.class);
        this.inputFactory = XMLInputFactory.newFactory();
        this.inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        this.inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    }

    Order unmarshal(java.io.InputStream xml) throws Exception {
        XMLStreamReader reader = inputFactory.createXMLStreamReader(xml);
        try {
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return (Order) unmarshaller.unmarshal(reader);
        } finally {
            reader.close();
        }
    }
}

class Order {
    public String id;
    public String item;
}
