import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class N02_ConstantExpression {
    public Object safe(String unusedUserLabel) {
        ExpressionParser parser = new SpelExpressionParser();
        // Expression text is constant; user value not used as expression
        return parser.parseExpression("'fixed-lab-marker'")
                .getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build());
    }
}
