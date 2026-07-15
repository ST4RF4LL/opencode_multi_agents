import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.math.BigDecimal;

@RestController
public class P02_RequestBodyAccountBalance {
    private final AccountRepository accountRepository = new AccountRepository();

    @PutMapping("/accounts")
    public Account vulnerable(@RequestBody Account account) {
        return accountRepository.save(account);
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
        public BigDecimal getBalance() { return balance; }
        public void setBalance(BigDecimal balance) { this.balance = balance; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }

    static class AccountRepository {
        Account save(Account a) { return a; }
    }
}
