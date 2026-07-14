public class P03_OrderByInject {
    public String build(String base, String sort) {
        return base + " ORDER BY " + sort;
    }
}
