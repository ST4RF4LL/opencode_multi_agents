import java.util.Set;

public class N03_OrderByAllowlist {
    private static final Set<String> ALLOWED = Set.of("id", "name", "email");

    public String safe(String base, String sort) {
        String col = ALLOWED.contains(sort) ? sort : "id";
        return base + " ORDER BY " + col;
    }
}
