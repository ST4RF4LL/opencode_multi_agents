import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;

public class N05_NimbusProcessorConfigured {
    public JWTClaimsSet safe(String token) throws Exception {
        JWKSource<SecurityContext> jwkSource =
                new RemoteJWKSet<>(new URL("https://issuer.example.invalid/jwks"));
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        processor.setJWTClaimsSetVerifier(
                new DefaultJWTClaimsVerifier<>(
                        new JWTClaimsSet.Builder().issuer("https://issuer.example.invalid").build(),
                        new HashSet<>(Arrays.asList("sub", "iat", "exp", "aud"))));

        return processor.process(token, null);
    }
}
