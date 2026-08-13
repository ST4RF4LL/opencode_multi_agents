import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class ParsedUrlStoredButNeverExecuted {
  private final ObjectMapper mapper;
  private final JobRepository jobs;

  void importJob(String json) throws Exception {
    JsonNode document = mapper.readTree(json);
    jobs.save(new Job(document.get("api").asText()));
  }
}
