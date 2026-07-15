import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class N02_SnakeYamlSafeConstructor {
    public Object safe(String yaml) {
        return new Yaml(new SafeConstructor()).load(yaml);
    }
}
