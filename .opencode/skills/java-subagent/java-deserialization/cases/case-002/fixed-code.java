import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    static {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
        ParserConfig.getGlobalInstance().setSafeMode(true);
    }

    public static class OrderDto {
        public String id;
        public int qty;
    }

    @PostMapping("/api/json")
    public OrderDto parse(@RequestBody String body) {
        return JSON.parseObject(body, OrderDto.class);
    }
}
