import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.Authentication;
import java.util.Optional;

public class N01_FindByIdAndUserId {
    interface OrderRepository extends JpaRepository<Order, Long> {
        Optional<Order> findByIdAndUserId(Long id, Long userId);
    }
    static class Order {
        Long id;
        Long userId;
    }

    private final OrderRepository orderRepository;

    public N01_FindByIdAndUserId(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order safe(Long id, Authentication authentication) {
        Long currentUserId = Long.valueOf(authentication.getName());
        return orderRepository.findByIdAndUserId(id, currentUserId).orElseThrow();
    }
}
