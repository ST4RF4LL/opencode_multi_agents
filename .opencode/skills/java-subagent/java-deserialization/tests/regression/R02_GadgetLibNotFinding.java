// Regression: gadget library import alone must NOT become a Finding
// commons-collections may appear on classpath as amplifier only
public class R02_GadgetLibNotFinding {
    public String noDeserialPath(String name) {
        return "hello-" + name;
    }
}
