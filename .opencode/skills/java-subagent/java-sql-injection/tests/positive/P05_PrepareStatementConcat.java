import java.sql.*;

public class P05_PrepareStatementConcat {
    public PreparedStatement vulnerable(Connection c, String id) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        return c.prepareStatement(sql);
    }
}
