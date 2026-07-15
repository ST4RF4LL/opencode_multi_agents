import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.jpa.repository.JpaRepository;

interface R01OrderRepository extends JpaRepository<R01Order, Long> {}

class R01Order {
    public Long id;
    public Long userId;
}

@RestController
public class R01_PathVariableFindById {
    private final R01OrderRepository orderRepository;

    public R01_PathVariableFindById(R01OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @GetMapping("/api/orders/{id}")
    public R01Order get(@PathVariable Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
