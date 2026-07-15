import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApi {
    private final UserRepository userRepository;

    public UserApi(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PutMapping("/api/users/{id}")
    public UserEntity update(@PathVariable Long id, @RequestBody UserEntity body) {
        UserEntity entity = userRepository.findById(id);
        BeanUtils.copyProperties(body, entity);
        return userRepository.save(entity);
    }
}

class UserEntity {
    private Long id;
    private String displayName;
    private String email;
    private boolean isAdmin;
    private String role;
    private String passwordHash;

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
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
}

interface UserRepository {
    UserEntity findById(Long id);
    UserEntity save(UserEntity user);
}
