import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N04_BeanUtilsWithIgnoreList {
    private final UserRepository userRepository = new UserRepository();

    @PutMapping("/users/{id}")
    public UserEntity safe(@PathVariable Long id, @RequestBody UserEntity body) {
        UserEntity entity = userRepository.findById(id);
        BeanUtils.copyProperties(body, entity, "id", "admin", "role", "passwordHash", "isAdmin");
        return userRepository.save(entity);
    }

    static class UserEntity {
        private Long id;
        private String displayName;
        private boolean isAdmin;
        private String role;
        private String passwordHash;

        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        public String getPasswordHash() { return passwordHash; }
        public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    }

    static class UserRepository {
        UserEntity findById(Long id) { return new UserEntity(); }
        UserEntity save(UserEntity u) { return u; }
    }
}
