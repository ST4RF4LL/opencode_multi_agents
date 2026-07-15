// Pattern: StandardEvaluationContext vuln vs SimpleEvaluationContext fix contrast
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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

    Object evaluate(String expression) {
        // Vulnerable: full SpEL power
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression exp = parser.parseExpression(expression);
        return exp.getValue(context);
    }
}
