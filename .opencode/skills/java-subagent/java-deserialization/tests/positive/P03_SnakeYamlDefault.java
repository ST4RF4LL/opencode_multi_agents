import org.yaml.snakeyaml.Yaml;

public class P03_SnakeYamlDefault {
    public Object vulnerable(String yaml) {
        return new Yaml().load(yaml);
    }
}
