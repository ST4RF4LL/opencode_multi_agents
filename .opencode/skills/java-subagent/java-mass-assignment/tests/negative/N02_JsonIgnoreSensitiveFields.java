import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.math.BigDecimal;

@RestController
public class N02_JsonIgnoreSensitiveFields {
    private final AccountRepository accountRepository = new AccountRepository();

    @PutMapping("/accounts")
    public Account safe(@RequestBody Account account) {
        Account existing = accountRepository.findById(account.getId());
        existing.setDisplayName(account.getDisplayName());
        return accountRepository.save(existing);
    }

    static class Account {
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

    static class AccountRepository {
        Account findById(Long id) { return new Account(); }
        Account save(Account a) { return a; }
    }
}
