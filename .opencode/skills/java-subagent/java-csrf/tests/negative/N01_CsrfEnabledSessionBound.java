import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Configuration
class N01_Security {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF remains enabled (default) for session form login
        http.formLogin(form -> form.permitAll())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
public class N01_CsrfEnabledSessionBound {
    @PostMapping("/account/password")
    public String changePassword(@RequestParam String newPassword) {
        return "changed";
    }
}
