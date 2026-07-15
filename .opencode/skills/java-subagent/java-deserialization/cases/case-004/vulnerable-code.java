// Pattern: Jackson default typing
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PolyController {
    private final ObjectMapper mapper = new ObjectMapper();

    public PolyController() {
        mapper.enableDefaultTyping();
    }

    @PostMapping("/api/poly")
    public Object read(@RequestBody String json) throws Exception {
        return mapper.readValue(json, Object.class);
    }
}
