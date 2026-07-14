import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class UserDao {
    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findById(HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        String sql = "SELECT id, name, email FROM users WHERE id = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, id);
        return ps.executeQuery();
    }
}
