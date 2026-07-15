import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class P04_ReaderForUpdatingPatch {
    private final ObjectMapper mapper = new ObjectMapper();
    private final UserRepository userRepository = new UserRepository();

    @PatchMapping("/users/{id}")
    public UserEntity vulnerable(@PathVariable Long id, @RequestBody String json) throws Exception {
        UserEntity entity = userRepository.findById(id);
        mapper.readerForUpdating(entity).readValue(json);
        return userRepository.save(entity);
    }

    static class UserEntity {
        private Long id;
        private String displayName;
        private boolean isAdmin;
        private String role;

        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }

    static class UserRepository {
        UserEntity findById(Long id) { return new UserEntity(); }
        UserEntity save(UserEntity u) { return u; }
    }
}
