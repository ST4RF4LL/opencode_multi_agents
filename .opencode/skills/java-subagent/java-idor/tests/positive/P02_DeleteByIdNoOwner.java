import org.springframework.data.jpa.repository.JpaRepository;

public class P02_DeleteByIdNoOwner {
    interface UserRepository extends JpaRepository<User, Long> {}
    static class User {
        Long id;
    }

    private final UserRepository userRepository;

    public P02_DeleteByIdNoOwner(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void vulnerable(Long id) {
        userRepository.deleteById(id);
    }
}
