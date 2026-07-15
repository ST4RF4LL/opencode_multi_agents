// Pattern: JAXB Unmarshaller insecure config (raw InputStream, no hardened StAX)
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

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

    JaxbOrderService() throws Exception {
        this.context = JAXBContext.newInstance(Order.class);
    }

    Order unmarshal(java.io.InputStream xml) throws Exception {
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (Order) unmarshaller.unmarshal(xml);
    }
}

class Order {
    public String id;
    public String item;
}
