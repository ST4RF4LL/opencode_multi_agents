import java.sql.*;

public class P01_JdbcConcat {
    public ResultSet vulnerable(Connection c, String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        return c.createStatement().executeQuery(sql);
    }
}
