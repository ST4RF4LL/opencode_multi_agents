import com.fasterxml.jackson.databind.ObjectMapper;

public class N03_JacksonClosedDto {
    public static class UserDto {
        public String name;
    }

    private final ObjectMapper mapper = new ObjectMapper();

    public UserDto safe(String json) throws Exception {
        return mapper.readValue(json, UserDto.class);
    }
}
