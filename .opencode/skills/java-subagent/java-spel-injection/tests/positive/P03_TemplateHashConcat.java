import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class P03_TemplateHashConcat {
    public String vulnerable(String name) {
        ExpressionParser parser = new SpelExpressionParser();
        String template = "Hello #{'" + name + "'}";
        Expression exp = parser.parseExpression(template, new TemplateParserContext());
        return String.valueOf(exp.getValue(new StandardEvaluationContext()));
    }
}
