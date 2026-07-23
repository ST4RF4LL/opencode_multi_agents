import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class N06_ChildCrudBoundToAuthorizedParent {
    interface ProjectService { void requireAccess(Authentication principal, Long projectId); }
    interface IssueRepository extends JpaRepository<Issue, Long> {
        Optional<Issue> findByIdAndProjectId(Long issueId, Long projectId);
    }
    static class Issue { Long id; Long projectId; }

    private final ProjectService projects;
    private final IssueRepository issues;

    public N06_ChildCrudBoundToAuthorizedParent(ProjectService projects, IssueRepository issues) {
        this.projects = projects;
        this.issues = issues;
    }

    @GetMapping("/projects/{projectId}/issues/{issueId}")
    public Issue get(@PathVariable Long projectId, @PathVariable Long issueId, Authentication principal) {
        projects.requireAccess(principal, projectId);
        return issues.findByIdAndProjectId(issueId, projectId).orElseThrow();
    }
}
