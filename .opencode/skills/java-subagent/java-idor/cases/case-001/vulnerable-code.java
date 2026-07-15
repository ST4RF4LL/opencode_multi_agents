import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

interface OrderRepository extends JpaRepository<Order, Long> {}

class Order {
    public Long id;
    public Long userId;
    public String details;
}

@RestController
public class OrderController {
    private final OrderRepository orderRepository;

    public OrderController(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("not found"));
    }
}
