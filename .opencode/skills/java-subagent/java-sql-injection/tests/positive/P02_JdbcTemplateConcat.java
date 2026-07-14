import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

public class P02_JdbcTemplateConcat {
    private final JdbcTemplate jdbc;

    public P02_JdbcTemplateConcat(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> vulnerable(String name) {
        return jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
