import java.sql.*;

public class N05_ConstantSql {
    public ResultSet safe(Connection c) throws SQLException {
        return c.createStatement().executeQuery("SELECT count(*) FROM users");
    }
}
