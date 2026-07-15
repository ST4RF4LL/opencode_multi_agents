import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class P05_StringFormatSpel {
    public Object vulnerable(String userPart) {
        ExpressionParser parser = new SpelExpressionParser();
        String expr = String.format("#{%s}", userPart);
        return parser.parseExpression(expr).getValue(new StandardEvaluationContext());
    }
}
