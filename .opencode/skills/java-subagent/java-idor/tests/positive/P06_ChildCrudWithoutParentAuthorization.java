import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class P06_ChildCrudWithoutParentAuthorization {
    interface IssueRepository extends JpaRepository<Issue, Long> {}
    static class Issue { Long id; Long projectId; }

    private final IssueRepository issues;

    public P06_ChildCrudWithoutParentAuthorization(IssueRepository issues) {
        this.issues = issues;
    }

    @GetMapping("/projects/{projectId}/issues/{issueId}")
    public Issue get(@PathVariable Long projectId, @PathVariable Long issueId) {
        // projectId is decorative: neither parent authorization nor issue.projectId binding occurs.
        return issues.findById(issueId).orElseThrow();
    }
}
