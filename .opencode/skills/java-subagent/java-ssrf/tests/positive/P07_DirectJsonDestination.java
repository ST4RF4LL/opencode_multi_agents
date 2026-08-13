import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.web.client.RestTemplate;

class DirectJsonDestination {
  private final RestTemplate client;

  String fetch(JsonNode document) {
    return client.getForObject(document.get("url").asText(), String.class);
  }
}
