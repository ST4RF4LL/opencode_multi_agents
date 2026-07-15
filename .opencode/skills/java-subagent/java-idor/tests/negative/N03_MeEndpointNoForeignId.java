import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.Authentication;
import java.util.List;

public class N03_MeEndpointNoForeignId {
    interface OrderRepository extends JpaRepository<Order, Long> {
        List<Order> findByUserId(Long userId);
    }
    static class Order {
        Long id;
        Long userId;
    }

    private final OrderRepository orderRepository;

    public N03_MeEndpointNoForeignId(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public List<Order> safe(Authentication authentication) {
        Long currentUserId = Long.valueOf(authentication.getName());
        return orderRepository.findByUserId(currentUserId);
    }
}
