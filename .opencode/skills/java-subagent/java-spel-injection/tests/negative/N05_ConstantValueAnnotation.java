import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class N05_ConstantValueAnnotation {
    // Compile-time constant SpEL / property placeholder — not user SpEL injection
    @Value("#{systemProperties['user.home']}")
    private String home;

    @Value("${app.name}")
    private String appName;

    public String getHome() {
        return home;
    }

    public String getAppName() {
        return appName;
    }
}
