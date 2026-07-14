import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class R01_HtmlPolicySanitizer {
    private static final PolicyFactory POLICY =
            Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);

    public String sanitizeUserHtml(String userHtml) {
        return POLICY.sanitize(userHtml);
    }
}
