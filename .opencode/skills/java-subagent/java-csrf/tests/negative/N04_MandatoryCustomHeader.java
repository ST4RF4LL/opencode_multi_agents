import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class N04_MandatoryCustomHeader {
    public static class Body {
        public String email;
    }

    @PostMapping(path = "/api/profile/email", consumes = "application/json")
    public String update(@RequestHeader("X-CSRF-TOKEN") String csrf,
                         @RequestBody Body body) {
        if (csrf == null || csrf.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        // assume server also binds token to session via filter
        return "updated";
    }
}
