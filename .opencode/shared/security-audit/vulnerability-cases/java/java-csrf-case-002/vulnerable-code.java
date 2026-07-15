import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Configuration
class ApiSecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
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
    public String update(@RequestBody ProfileUpdate body) {
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
