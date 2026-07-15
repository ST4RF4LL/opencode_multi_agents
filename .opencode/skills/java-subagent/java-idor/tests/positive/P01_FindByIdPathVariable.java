import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public class P01_FindByIdPathVariable {
    interface OrderRepository extends JpaRepository<Order, Long> {}
    static class Order {
        Long id;
        Long userId;
    }

    private final OrderRepository orderRepository;

    public P01_FindByIdPathVariable(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order vulnerable(Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
