import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.client.RestTemplate;

class PersistedJsonUrlExecutedByWorker {
  private final ObjectMapper mapper;
  private final JobRepository jobs;
  private final RestTemplate client;

  void importJob(String json) throws Exception {
    JsonNode document = mapper.readTree(json);
    jobs.save(new Job(document.get("api").asText()));
  }

  String execute(String jobId) {
    Job job = jobs.findById(jobId).orElseThrow();
    return client.getForObject(job.api(), String.class);
  }
}
