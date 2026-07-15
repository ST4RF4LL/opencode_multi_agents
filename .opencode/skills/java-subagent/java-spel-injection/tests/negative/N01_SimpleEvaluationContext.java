import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class N01_SimpleEvaluationContext {
    public Object safe(DemoRoot root) {
        ExpressionParser parser = new SpelExpressionParser();
        // Constant expression; restricted context
        Expression exp = parser.parseExpression("name");
        SimpleEvaluationContext context =
                SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(root).build();
        return exp.getValue(context);
    }

    public static class DemoRoot {
        private final String name;
        public DemoRoot(String name) { this.name = name; }
        public String getName() { return name; }
    }
}
