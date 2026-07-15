import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class N05_NoSensitiveFieldsDto {
    @PostMapping("/comments")
    public CommentRequest safe(@RequestBody CommentRequest request) {
        return request;
    }

    static class CommentRequest {
        private String body;
        private String authorDisplayName;

        public String getBody() { return body; }
        public void setBody(String body) { this.body = body; }
        public String getAuthorDisplayName() { return authorDisplayName; }
        public void setAuthorDisplayName(String authorDisplayName) {
            this.authorDisplayName = authorDisplayName;
        }
    }
}
