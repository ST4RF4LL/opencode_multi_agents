import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SearchController {
    @GetMapping("/search")
    public String search(@RequestParam("q") String q, Model model) {
        model.addAttribute("q", q);
        return "search";
    }
}

/*
// search.jsp (fixed) — encode at template boundary
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<body>
  <p>Results for: <c:out value="${q}"/></p>
</body>
</html>
*/
