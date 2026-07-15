import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.Authentication;
import java.util.Optional;

public class N04_ServerTenantContext {
    interface DocumentRepository extends JpaRepository<Document, Long> {
        Optional<Document> findByTenantIdAndId(Long tenantId, Long id);
    }
    static class Document {
        Long id;
        Long tenantId;
    }
    static class TenantPrincipal {
        Long tenantId;
        Long userId;
    }

    private final DocumentRepository documentRepository;

    public N04_ServerTenantContext(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }

    public Document safe(Long id, Authentication authentication) {
        TenantPrincipal principal = (TenantPrincipal) authentication.getPrincipal();
        return documentRepository.findByTenantIdAndId(principal.tenantId, id).orElseThrow();
    }
}
