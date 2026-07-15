import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

public class N04_FastjsonSafeMode {
    public static class OrderDto {
        public String id;
    }

    static {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
        ParserConfig.getGlobalInstance().setSafeMode(true);
    }

    public OrderDto safe(String body) {
        return JSON.parseObject(body, OrderDto.class);
    }
}
