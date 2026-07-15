import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.jpa.repository.JpaRepository;

interface UserRepository extends JpaRepository<User, Long> {}

class User {
    public Long id;
    public String username;
    public String role;
}

@RestController
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id.toString() == authentication.name")
    public void deleteUser(@PathVariable Long id, Authentication authentication) {
        userRepository.deleteById(id);
    }
}
