import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Configuration
class P01_Security {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}

@RestController
public class P01_SpringCsrfDisablePasswordPost {
    @PostMapping("/account/password")
    public String changePassword(@RequestParam String newPassword) {
        return "changed:" + newPassword;
    }
}
