import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PreAuthorize;

public class N05_AdminOnlyDelete {
    interface UserRepository extends JpaRepository<User, Long> {}
    static class User {
        Long id;
    }

    private final UserRepository userRepository;

    public N05_AdminOnlyDelete(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void safe(Long id) {
        userRepository.deleteById(id);
    }
}
