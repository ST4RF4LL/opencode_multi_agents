// Pattern: MyBatis ORDER BY ${sort} identifier injection
// Mapper interface + XML dynamic SQL

import org.apache.ibatis.annotations.Param;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

interface UserMapper {
    List<User> selectUsers(@Param("sort") String sort);
}

@RestController
class UserController {
    private final UserMapper userMapper;

    UserController(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @GetMapping("/api/users")
    public List<User> list(@RequestParam String sort) {
        return userMapper.selectUsers(sort);
    }
}

// UserMapper.xml (co-located pattern):
// <select id="selectUsers" resultType="User">
//   SELECT id, name, email FROM users
//   ORDER BY ${sort}
// </select>

class User {
    public long id;
    public String name;
    public String email;
}
