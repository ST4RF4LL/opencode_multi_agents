import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.Map;
import java.util.Set;

public class N03_ExpressionAllowlist {
    private static final Set<String> ALLOWED = Set.of("name", "status");
    private static final Map<String, String> MAP = Map.of(
            "name", "name",
            "status", "status"
    );

    public Object safe(String key, Root root) {
        if (!ALLOWED.contains(key)) {
            throw new IllegalArgumentException("not allowed");
        }
        String expr = MAP.get(key);
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expr)
                .getValue(SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(root).build());
    }

    public static class Root {
        private final String name;
        private final String status;
        public Root(String name, String status) {
            this.name = name;
            this.status = status;
        }
        public String getName() { return name; }
        public String getStatus() { return status; }
    }
}
