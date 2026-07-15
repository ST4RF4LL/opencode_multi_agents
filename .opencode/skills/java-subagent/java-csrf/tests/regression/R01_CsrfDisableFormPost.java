import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Configuration
class R01_Security {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .formLogin(form -> form.permitAll())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
public class R01_CsrfDisableFormPost {
    @PostMapping("/account/password")
    public String changePassword(@RequestParam String newPassword) {
        return "ok";
    }
}
