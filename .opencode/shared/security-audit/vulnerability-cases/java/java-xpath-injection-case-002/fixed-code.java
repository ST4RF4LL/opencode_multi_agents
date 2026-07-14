import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

@RestController
class AuthController {
    private final XmlUserStore userStore;

    AuthController(XmlUserStore userStore) {
        this.userStore = userStore;
    }

    @PostMapping("/login")
    public boolean login(@RequestParam String username, @RequestParam String password)
            throws Exception {
        return userStore.authenticate(username, password);
    }
}

class XmlUserStore {
    private final Document usersXml;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    XmlUserStore(Document usersXml) {
        this.usersXml = usersXml;
    }

    boolean authenticate(String username, String password) throws Exception {
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            @Override
            public Object resolveVariable(QName variableName) {
                String local = variableName.getLocalPart();
                if ("username".equals(local)) {
                    return username;
                }
                if ("password".equals(local)) {
                    return password;
                }
                return null;
            }
        });
        String expr = "//user[name/text()=$username and password/text()=$password]";
        String result = xpath.evaluate(expr, usersXml);
        return result != null && !result.isEmpty();
    }
}
