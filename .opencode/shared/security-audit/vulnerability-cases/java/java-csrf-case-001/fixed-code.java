import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Configuration
class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF enabled by default for session/form login
            .formLogin(form -> form.permitAll())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class AccountController {
    private final UserService userService;

    AccountController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/account/password")
    public String changePassword(@RequestParam String newPassword) {
        // Spring CsrfFilter requires valid _csrf / header token bound to session
        userService.updatePassword(newPassword);
        return "ok";
    }
}

@Service
class UserService {
    public void updatePassword(String newPassword) {
        // persists password hash for current session user
    }
}
