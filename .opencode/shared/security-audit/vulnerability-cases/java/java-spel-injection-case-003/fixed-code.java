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
class ContextCompareController {
    private final ContextCompareService service;

    ContextCompareController(ContextCompareService service) {
        this.service = service;
    }

    @GetMapping("/api/context-eval")
    public Object eval(@RequestParam String expression) {
        return service.evaluate(expression);
    }
}

class ContextCompareService {
    private final ExpressionParser parser = new SpelExpressionParser();
    private static final Set<String> ALLOWED = Set.of("price", "qty", "total");
    private static final Map<String, String> EXPRESSION_MAP = Map.of(
            "price", "price",
            "qty", "qty",
            "total", "price * qty"
    );

    Object evaluate(String key) {
        String mapped = EXPRESSION_MAP.get(key);
        if (mapped == null || !ALLOWED.contains(key)) {
            throw new IllegalArgumentException("expression not allowed");
        }
        OrderRoot root = new OrderRoot(10, 2);
        // Fixed: restricted context + constant expression from allowlist
        SimpleEvaluationContext context =
                SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(root).build();
        Expression exp = parser.parseExpression(mapped);
        return exp.getValue(context);
    }

    static class OrderRoot {
        private final int price;
        private final int qty;

        OrderRoot(int price, int qty) {
            this.price = price;
            this.qty = qty;
        }

        public int getPrice() { return price; }
        public int getQty() { return qty; }
    }
}
