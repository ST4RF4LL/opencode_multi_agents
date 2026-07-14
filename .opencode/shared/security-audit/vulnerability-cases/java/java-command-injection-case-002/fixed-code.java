import java.io.IOException;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class JobController {
    private static final Set<String> ALLOWED_JOBS = Set.of("cleanup", "report", "healthcheck");

    private static final Map<String, String[]> JOB_ARGV = Map.of(
        "cleanup", new String[] {"/usr/local/bin/cleanup", "--safe"},
        "report", new String[] {"/usr/local/bin/report", "--daily"},
        "healthcheck", new String[] {"/usr/local/bin/healthcheck"}
    );

    private final JobRunner jobRunner;

    JobController(JobRunner jobRunner) {
        this.jobRunner = jobRunner;
    }

    @PostMapping("/api/jobs/run")
    public int run(@RequestParam String jobId) throws IOException, InterruptedException {
        if (!ALLOWED_JOBS.contains(jobId)) {
            throw new IllegalArgumentException("unknown job");
        }
        return jobRunner.executeFixed(JOB_ARGV.get(jobId));
    }
}

class JobRunner {
    public int executeFixed(String[] argv) throws IOException, InterruptedException {
        // List form, no shell, fully constant argv from allowlist map
        ProcessBuilder pb = new ProcessBuilder(argv);
        Process p = pb.start();
        return p.waitFor();
    }
}
