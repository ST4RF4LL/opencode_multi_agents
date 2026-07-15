import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ItemController {
    private final ItemRepository itemRepository;

    ItemController(ItemRepository itemRepository) {
        this.itemRepository = itemRepository;
    }

    @PostMapping("/items/delete")
    public String deletePost(@RequestParam long id) {
        // requires CSRF token when session cookie auth is used
        itemRepository.deleteById(id);
        return "deleted";
    }

    @DeleteMapping("/items/{id}")
    public String deleteRest(@RequestParam long id) {
        itemRepository.deleteById(id);
        return "deleted";
    }
}

@Repository
class ItemRepository {
    public void deleteById(long id) {
        // deletes item with authorization checks
    }
}
