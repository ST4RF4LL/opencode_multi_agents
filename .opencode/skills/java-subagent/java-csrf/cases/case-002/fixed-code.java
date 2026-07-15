import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
class ApiSecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class ProfileController {
    private final ProfileService profileService;

    ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    public static class ProfileUpdate {
        public String email;
    }

    @PostMapping(path = "/api/profile/email", consumes = "application/json")
    public String update(@RequestBody ProfileUpdate body, HttpServletRequest request) {
        String header = request.getHeader("X-XSRF-TOKEN");
        if (header == null || header.isBlank()) {
            // Defense-in-depth: framework CsrfFilter also validates
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "CSRF token required");
        }
        profileService.updateEmail(body.email);
        return "updated";
    }
}

@Service
class ProfileService {
    public void updateEmail(String email) {
        // updates email for current session user
    }
}
