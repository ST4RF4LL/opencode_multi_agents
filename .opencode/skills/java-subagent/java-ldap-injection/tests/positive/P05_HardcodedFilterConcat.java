import org.springframework.ldap.filter.HardcodedFilter;
import org.springframework.web.bind.annotation.RequestParam;

/** Positive: HardcodedFilter with concatenated user input. */
public class P05_HardcodedFilterConcat {
    public HardcodedFilter build(@RequestParam String name) {
        return new HardcodedFilter("(cn=" + name + ")");
    }
}
