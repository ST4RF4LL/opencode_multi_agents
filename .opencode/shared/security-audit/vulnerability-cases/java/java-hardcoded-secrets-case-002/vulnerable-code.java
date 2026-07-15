// Pattern: Spring app loads plaintext datasource password from application.yml
// Companion config: application.yml in this case directory.
import org.springframework.boot.jdbc.DataSourceBuilder;
import javax.sql.DataSource;

public class DataSourceConfig {
    // Mirrors values typically bound from application.yml
    public DataSource dataSource() {
        return DataSourceBuilder.create()
            .url("jdbc:mysql://db.example.invalid:3306/appdb")
            .username("app_user")
            .password("CHANGE_ME_NOT_REAL")
            .build();
    }
}
