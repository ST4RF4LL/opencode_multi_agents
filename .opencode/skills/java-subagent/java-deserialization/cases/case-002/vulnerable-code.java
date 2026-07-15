// Pattern: Fastjson autoType / @type
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    static {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    @PostMapping("/api/json")
    public Object parse(@RequestBody String body) {
        // Attacker-controlled JSON may include type id selecting arbitrary classes
        return JSON.parseObject(body);
    }
}
