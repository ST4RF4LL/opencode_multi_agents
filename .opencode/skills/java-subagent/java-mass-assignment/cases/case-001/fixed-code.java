import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("displayName", "email");
    }

    @PostMapping("/api/users/profile")
    @ResponseBody
    public UserEntity updateProfile(@ModelAttribute UserUpdateRequest request) {
        UserEntity user = userRepository.findById(request.getId());
        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        return userRepository.save(user);
    }
}

class UserUpdateRequest {
    private Long id;
    private String displayName;
    private String email;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

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
    UserEntity findById(Long id);
}
