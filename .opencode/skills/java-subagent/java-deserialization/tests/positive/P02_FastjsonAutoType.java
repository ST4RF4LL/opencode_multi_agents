import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

public class P02_FastjsonAutoType {
    static {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    public Object vulnerable(String body) {
        return JSON.parseObject(body);
    }
}
