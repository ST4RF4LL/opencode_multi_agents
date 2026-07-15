import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

interface DocumentRepository extends JpaRepository<Document, Long> {
    Optional<Document> findByTenantIdAndId(Long tenantId, Long id);
}

class Document {
    public Long id;
    public Long tenantId;
    public String content;
}

class TenantPrincipal {
    public final Long tenantId;
    public final Long userId;
    public TenantPrincipal(Long tenantId, Long userId) {
        this.tenantId = tenantId;
        this.userId = userId;
    }
}

@RestController
public class DocumentController {
    private final DocumentRepository documentRepository;

    public DocumentController(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }

    @GetMapping("/documents/{id}")
    public Document getDocument(@PathVariable Long id, Authentication authentication) {
        TenantPrincipal principal = (TenantPrincipal) authentication.getPrincipal();
        Long tenantId = principal.tenantId;
        return documentRepository.findByTenantIdAndId(tenantId, id)
            .orElseThrow(() -> new IllegalArgumentException("not found"));
    }
}
