import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P03_GetBasedDelete {
    private final SimpleRepo repo = new SimpleRepo();

    @GetMapping("/items/delete")
    public String delete(@RequestParam long id) {
        repo.deleteById(id);
        return "deleted";
    }

    static class SimpleRepo {
        void deleteById(long id) {
            // state-changing delete
        }
    }
}
