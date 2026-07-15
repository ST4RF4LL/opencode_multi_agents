// Pattern: parseExpression(userInput) + StandardEvaluationContext getValue
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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

    Object run(String expression) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression exp = parser.parseExpression(expression);
        return exp.getValue(context);
    }
}
