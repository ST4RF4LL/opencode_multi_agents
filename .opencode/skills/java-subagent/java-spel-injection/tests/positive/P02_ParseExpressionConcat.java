import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class P02_ParseExpressionConcat {
    public Object vulnerable(String field) {
        ExpressionParser parser = new SpelExpressionParser();
        String expr = "#root." + field;
        Expression exp = parser.parseExpression(expr);
        return exp.getValue(new StandardEvaluationContext());
    }
}
