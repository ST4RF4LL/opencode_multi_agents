import com.thoughtworks.xstream.XStream;

public class P05_XStreamFromXml {
    public Object vulnerable(String xml) {
        XStream xs = new XStream();
        return xs.fromXML(xml);
    }
}
