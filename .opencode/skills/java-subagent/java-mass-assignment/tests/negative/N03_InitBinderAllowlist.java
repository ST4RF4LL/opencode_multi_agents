import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N03_InitBinderAllowlist {
    private final UserRepository userRepository = new UserRepository();

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("displayName", "email");
    }

    @PostMapping("/profile")
    public UserEntity safe(@ModelAttribute UserEntity user) {
        return userRepository.save(user);
    }

    static class UserEntity {
        private String displayName;
        private String email;
        private boolean isAdmin;
        private String role;

        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }

    static class UserRepository {
        UserEntity save(UserEntity u) { return u; }
    }
}
