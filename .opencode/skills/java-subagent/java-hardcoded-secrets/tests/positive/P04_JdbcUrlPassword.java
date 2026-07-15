import java.sql.Connection;
import java.sql.DriverManager;

public class P04_JdbcUrlPassword {
    public Connection vulnerable() throws Exception {
        return DriverManager.getConnection(
            "jdbc:mysql://db.example.invalid:3306/appdb",
            "root",
            "CHANGE_ME_NOT_REAL"
        );
    }
}
