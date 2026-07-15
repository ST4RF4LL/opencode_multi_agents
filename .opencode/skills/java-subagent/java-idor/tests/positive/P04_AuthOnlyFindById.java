import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PreAuthorize;

public class P04_AuthOnlyFindById {
    interface InvoiceRepository extends JpaRepository<Invoice, Long> {}
    static class Invoice {
        Long id;
        Long ownerId;
    }

    private final InvoiceRepository invoiceRepository;

    public P04_AuthOnlyFindById(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    @PreAuthorize("isAuthenticated()")
    public Invoice vulnerable(Long id) {
        return invoiceRepository.findById(id).orElseThrow();
    }
}
