import org.springframework.web.servlet.view.RedirectView;

public class P05_redirectview_user {
    public RedirectView vulnerable(String target) {
        return new RedirectView(target);
    }
}
