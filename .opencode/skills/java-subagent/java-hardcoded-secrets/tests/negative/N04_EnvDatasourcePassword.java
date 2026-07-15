import org.springframework.boot.jdbc.DataSourceBuilder;
import javax.sql.DataSource;

public class N04_EnvDatasourcePassword {
    public DataSource safe() {
        String password = System.getenv("SPRING_DATASOURCE_PASSWORD");
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("SPRING_DATASOURCE_PASSWORD required");
        }
        return DataSourceBuilder.create()
            .url(System.getenv("SPRING_DATASOURCE_URL"))
            .username(System.getenv("SPRING_DATASOURCE_USERNAME"))
            .password(password)
            .build();
    }
}
