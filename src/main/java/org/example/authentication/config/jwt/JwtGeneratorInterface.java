package org.example.authentication.config.jwt;

import org.springframework.security.core.Authentication;

import java.util.Map;

public interface JwtGeneratorInterface {
    Map<String, String> generateToken(Authentication authentication);
    Authentication getAuthentication(String token);
    boolean validateToken(String authToken);
    void disableAccessToken(String token);
}
