import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.math.BigDecimal;

@RestController
public class AccountController {
    private final AccountRepository accountRepository;

    public AccountController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @PutMapping("/api/accounts")
    public Account update(@RequestBody Account account) {
        return accountRepository.save(account);
    }
}

class Account {
    private Long id;
    private String displayName;
    private BigDecimal balance;
    private String role;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}

interface AccountRepository {
    Account save(Account account);
}
