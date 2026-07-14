import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

public class N02_JdbcTemplateBound {
    private final JdbcTemplate jdbc;

    public N02_JdbcTemplateBound(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> safe(String name) {
        return jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
    }
}
