// Regression: user string to parseExpression must remain a positive candidate
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class R01_ParseExpressionUser {
    public Object mustDetect(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expression).getValue(new StandardEvaluationContext());
    }
}
