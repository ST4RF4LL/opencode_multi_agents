import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PolyController {
    private final ObjectMapper mapper = new ObjectMapper();

    public static class EventDto {
        public String type;
        public String payload;
    }

    @PostMapping("/api/poly")
    public EventDto read(@RequestBody String json) throws Exception {
        // No default typing; closed DTO only
        return mapper.readValue(json, EventDto.class);
    }
}
