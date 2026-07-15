import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
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
    private static final String TEMPLATE = "Hello #{#name}";

    String render(String name) {
        // Constant template; user value bound as variable only
        Expression exp = parser.parseExpression(TEMPLATE, new TemplateParserContext());
        SimpleEvaluationContext context =
                SimpleEvaluationContext.forReadOnlyDataBinding().build();
        context.setVariable("name", name);
        return String.valueOf(exp.getValue(context));
    }
}
