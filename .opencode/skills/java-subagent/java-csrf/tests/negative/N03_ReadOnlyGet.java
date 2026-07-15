import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N03_ReadOnlyGet {
    @GetMapping("/items/{id}")
    public String get(@PathVariable long id) {
        return "item:" + id;
    }
}
