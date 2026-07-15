import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

@RestController
class SpelEvalController {
    private final SpelEvalService service;

    SpelEvalController(SpelEvalService service) {
        this.service = service;
    }

    @GetMapping("/api/eval")
    public Object evaluate(@RequestParam String expression) {
        return service.run(expression);
    }
}

class SpelEvalService {
    private final ExpressionParser parser = new SpelExpressionParser();
    private static final Set<String> ALLOWED = Set.of("name", "status", "count");

    private static final Map<String, String> EXPRESSION_MAP = Map.of(
            "name", "name",
            "status", "status",
            "count", "count"
    );

    Object run(String fieldKey) {
        String mapped = EXPRESSION_MAP.get(fieldKey);
        if (mapped == null || !ALLOWED.contains(fieldKey)) {
            throw new IllegalArgumentException("expression not allowed");
        }
        // Constant expression text only; bind data as root, not expression string
        DemoRoot root = new DemoRoot("lab", "ok", 1);
        SimpleEvaluationContext context =
                SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(root).build();
        Expression exp = parser.parseExpression(mapped);
        return exp.getValue(context);
    }

    static class DemoRoot {
        private final String name;
        private final String status;
        private final int count;

        DemoRoot(String name, String status, int count) {
            this.name = name;
            this.status = status;
            this.count = count;
        }

        public String getName() { return name; }
        public String getStatus() { return status; }
        public int getCount() { return count; }
    }
}
