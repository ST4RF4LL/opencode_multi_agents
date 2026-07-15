// Regression: static API key constant must remain detectable
public class R01_StaticApiKey {
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";

    public String authHeader() {
        return "Bearer " + API_KEY;
    }
}
