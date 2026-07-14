import org.apache.ibatis.annotations.Param;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
import java.util.Map;
import java.util.Set;

interface UserMapper {
    List<User> selectUsers(@Param("sortColumn") String sortColumn);
}

@RestController
class UserController {
    private static final Set<String> ALLOWED_SORT =
        Set.of("id", "name", "email", "created_at");

    private final UserMapper userMapper;

    UserController(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @GetMapping("/api/users")
    public List<User> list(@RequestParam(defaultValue = "id") String sort) {
        String sortColumn = ALLOWED_SORT.contains(sort) ? sort : "id";
        return userMapper.selectUsers(sortColumn);
    }
}

// UserMapper.xml:
// ORDER BY ${sortColumn}  -- value is allowlisted constant only
// Prefer: CASE mapping in SQL or static column enum without user-controlled ${}

class User {
    public long id;
    public String name;
    public String email;
}
