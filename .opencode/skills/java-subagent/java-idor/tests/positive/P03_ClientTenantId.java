import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public class P03_ClientTenantId {
    interface DocumentRepository extends JpaRepository<Document, Long> {
        Optional<Document> findByTenantIdAndId(Long tenantId, Long id);
    }
    static class Document {
        Long id;
        Long tenantId;
    }

    private final DocumentRepository documentRepository;

    public P03_ClientTenantId(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }

    public Document vulnerable(Long id, Long tenantId) {
        return documentRepository.findByTenantIdAndId(tenantId, id).orElseThrow();
    }
}
