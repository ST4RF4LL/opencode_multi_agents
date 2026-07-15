import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N01_DedicatedDtoExplicitMap {
    private final UserRepository userRepository = new UserRepository();

    @PutMapping("/users")
    public UserEntity safe(@RequestBody UserUpdateDto dto) {
        UserEntity entity = userRepository.findById(dto.getId());
        entity.setDisplayName(dto.getDisplayName());
        entity.setEmail(dto.getEmail());
        return userRepository.save(entity);
    }

    static class UserUpdateDto {
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

    static class UserEntity {
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

    static class UserRepository {
        UserEntity findById(Long id) { return new UserEntity(); }
        UserEntity save(UserEntity u) { return u; }
    }
}
