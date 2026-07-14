import java.sql.*;

public class N01_PreparedBinding {
    public ResultSet safe(Connection c, String userId) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        return ps.executeQuery();
    }
}
