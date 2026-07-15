import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class P05_NestedRolesBinding {
    private final UserRepository userRepository = new UserRepository();

    @PostMapping("/users")
    public UserEntity vulnerable(@RequestBody UserEntity user) {
        return userRepository.save(user);
    }

    static class Role {
        private String name;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    static class UserEntity {
        private String displayName;
        private List<Role> roles;

        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public List<Role> getRoles() { return roles; }
        public void setRoles(List<Role> roles) { this.roles = roles; }
    }

    static class UserRepository {
        UserEntity save(UserEntity u) { return u; }
    }
}
