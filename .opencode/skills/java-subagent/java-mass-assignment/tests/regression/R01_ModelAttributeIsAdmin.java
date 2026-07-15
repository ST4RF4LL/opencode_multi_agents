import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Regression: @ModelAttribute UserEntity with isAdmin must remain a sink candidate.
 * Must not regress to false negative on classic Spring form over-posting.
 */
@RestController
public class R01_ModelAttributeIsAdmin {
    @PostMapping("/api/users/profile")
    public UserEntity update(@ModelAttribute UserEntity user) {
        return user;
    }

    static class UserEntity {
        private boolean isAdmin;
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
    }
}
