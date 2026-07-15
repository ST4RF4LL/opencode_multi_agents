import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("/api/users/profile")
    @ResponseBody
    public UserEntity updateProfile(@ModelAttribute UserEntity user) {
        return userRepository.save(user);
    }
}

// Domain entity used as form binding target — isAdmin is attacker-writable
class UserEntity {
    private Long id;
    private String displayName;
    private String email;
    private boolean isAdmin;
    private String role;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public boolean isAdmin() { return isAdmin; }
    public void setAdmin(boolean admin) { isAdmin = admin; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}

interface UserRepository {
    UserEntity save(UserEntity user);
}
