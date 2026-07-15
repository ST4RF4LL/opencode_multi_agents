import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

interface OrderRepository extends JpaRepository<Order, Long> {
    Optional<Order> findByIdAndUserId(Long id, Long userId);
}

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
    public Order getOrder(@PathVariable Long id, Authentication authentication) {
        Long currentUserId = Long.valueOf(authentication.getName());
        return orderRepository.findByIdAndUserId(id, currentUserId)
            .orElseThrow(() -> new IllegalArgumentException("not found"));
    }
}
