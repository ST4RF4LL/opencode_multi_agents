// Pattern: ProcessBuilder with shell wrapper (/bin/sh -c) and user-controlled script
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class JobController {
    private final JobRunner jobRunner;

    JobController(JobRunner jobRunner) {
        this.jobRunner = jobRunner;
    }

    @PostMapping("/api/jobs/run")
    public int run(@RequestParam String script) throws IOException, InterruptedException {
        return jobRunner.executeScript(script);
    }
}

class JobRunner {
    public int executeScript(String script) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", script);
        Process p = pb.start();
        return p.waitFor();
    }
}
