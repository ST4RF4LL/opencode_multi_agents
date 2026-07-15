import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ItemController {
    private final ItemRepository itemRepository;

    ItemController(ItemRepository itemRepository) {
        this.itemRepository = itemRepository;
    }

    @GetMapping("/items/delete")
    public String delete(@RequestParam long id) {
        itemRepository.deleteById(id);
        return "deleted";
    }
}

@Repository
class ItemRepository {
    public void deleteById(long id) {
        // deletes item owned by current session user or by id
    }
}
