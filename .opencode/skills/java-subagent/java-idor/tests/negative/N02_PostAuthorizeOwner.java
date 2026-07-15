import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PostAuthorize;

public class N02_PostAuthorizeOwner {
    interface OrderRepository extends JpaRepository<Order, Long> {}
    static class Order {
        Long id;
        Long userId;
        public Long getUserId() { return userId; }
    }

    private final OrderRepository orderRepository;

    public N02_PostAuthorizeOwner(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @PostAuthorize("returnObject.userId == authentication.principal.id")
    public Order safe(Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
