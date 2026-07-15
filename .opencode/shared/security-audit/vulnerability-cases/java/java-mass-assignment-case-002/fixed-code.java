import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
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
    public Account update(@RequestBody AccountUpdateRequest request) {
        Account account = accountRepository.findById(request.getId());
        account.setDisplayName(request.getDisplayName());
        return accountRepository.save(account);
    }
}

class AccountUpdateRequest {
    private Long id;
    private String displayName;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
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

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    public BigDecimal getBalance() { return balance; }

    @JsonIgnore
    public void setBalance(BigDecimal balance) { this.balance = balance; }

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    public String getRole() { return role; }

    @JsonIgnore
    public void setRole(String role) { this.role = role; }
}

interface AccountRepository {
    Account save(Account account);
    Account findById(Long id);
}
