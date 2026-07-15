import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class P04_StandardContextGetValue {
    public Object vulnerable(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        return parser.parseExpression(expression).getValue(ctx);
    }
}
