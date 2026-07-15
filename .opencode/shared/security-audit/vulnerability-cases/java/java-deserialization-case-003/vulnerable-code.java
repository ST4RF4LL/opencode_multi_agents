// Pattern: SnakeYAML default constructor
import org.yaml.snakeyaml.Yaml;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ConfigController {

    @PostMapping("/api/config/yaml")
    public Object load(@RequestBody String yaml) {
        Yaml parser = new Yaml();
        return parser.load(yaml);
    }
}
