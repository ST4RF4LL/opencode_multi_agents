import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.sql.DataSource;

@Configuration
public class DataSourceConfig {
    @Bean
    public DataSource dataSource() {
        String url = System.getenv("SPRING_DATASOURCE_URL");
        String user = System.getenv("SPRING_DATASOURCE_USERNAME");
        String password = System.getenv("SPRING_DATASOURCE_PASSWORD");
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("SPRING_DATASOURCE_PASSWORD must be set");
        }
        return DataSourceBuilder.create()
            .url(url)
            .username(user)
            .password(password)
            .build();
    }
}
