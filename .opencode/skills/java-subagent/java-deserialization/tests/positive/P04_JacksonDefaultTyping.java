import com.fasterxml.jackson.databind.ObjectMapper;

public class P04_JacksonDefaultTyping {
    private final ObjectMapper mapper = new ObjectMapper();

    public P04_JacksonDefaultTyping() {
        mapper.enableDefaultTyping();
    }

    public Object vulnerable(String json) throws Exception {
        return mapper.readValue(json, Object.class);
    }
}
