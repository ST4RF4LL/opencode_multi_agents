// Pattern: template string concat into #{...} with TemplateParserContext
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GreetingController {
    private final TemplateSpelService service;

    GreetingController(TemplateSpelService service) {
        this.service = service;
    }

    @GetMapping("/api/greet")
    public String greet(@RequestParam String name) {
        return service.render(name);
    }
}

class TemplateSpelService {
    private final ExpressionParser parser = new SpelExpressionParser();

    String render(String name) {
        // User input embedded into template expression slot
        String template = "Hello #{'" + name + "'}";
        Expression exp = parser.parseExpression(template, new TemplateParserContext());
        StandardEvaluationContext context = new StandardEvaluationContext();
        return String.valueOf(exp.getValue(context));
    }
}
