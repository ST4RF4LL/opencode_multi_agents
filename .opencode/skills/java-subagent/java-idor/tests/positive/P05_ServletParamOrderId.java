import javax.servlet.http.HttpServletRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public class P05_ServletParamOrderId {
    interface OrderRepository extends JpaRepository<Order, Long> {}
    static class Order {
        Long id;
        Long userId;
    }

    private final OrderRepository orderRepository;

    public P05_ServletParamOrderId(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order vulnerable(HttpServletRequest request) {
        Long orderId = Long.valueOf(request.getParameter("orderId"));
        return orderRepository.findById(orderId).orElseThrow();
    }
}
