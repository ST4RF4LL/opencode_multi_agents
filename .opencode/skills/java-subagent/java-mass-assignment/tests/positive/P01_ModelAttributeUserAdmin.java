import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P01_ModelAttributeUserAdmin {
    private final UserRepository userRepository = new UserRepository();

    @PostMapping("/profile")
    public UserEntity vulnerable(@ModelAttribute UserEntity user) {
        return userRepository.save(user);
    }

    static class UserEntity {
        private String displayName;
        private boolean isAdmin;
        private String role;

        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }

    static class UserRepository {
        UserEntity save(UserEntity u) { return u; }
    }
}
