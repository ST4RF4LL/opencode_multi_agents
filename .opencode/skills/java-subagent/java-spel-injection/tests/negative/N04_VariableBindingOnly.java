import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class N04_VariableBindingOnly {
    public String safe(String name) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression("Hello #{#name}", new TemplateParserContext());
        SimpleEvaluationContext context =
                SimpleEvaluationContext.forReadOnlyDataBinding().build();
        context.setVariable("name", name);
        return String.valueOf(exp.getValue(context));
    }
}
