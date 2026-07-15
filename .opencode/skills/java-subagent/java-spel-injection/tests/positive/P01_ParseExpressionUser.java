import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class P01_ParseExpressionUser {
    public Object vulnerable(String userExpr) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression exp = parser.parseExpression(userExpr);
        return exp.getValue(context);
    }
}
