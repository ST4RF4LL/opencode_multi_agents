import org.springframework.boot.jdbc.DataSourceBuilder;
import javax.sql.DataSource;

public class P02_DatasourcePassword {
    public DataSource vulnerable() {
        return DataSourceBuilder.create()
            .url("jdbc:mysql://db.example.invalid:3306/appdb")
            .username("app_user")
            .password("CHANGE_ME_NOT_REAL")
            .build();
    }
}
