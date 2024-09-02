package org.example.authentication.config.jwt;

import java.util.Map;

public interface JwtGeneratorInterface {
    Map<String, String> generateToken(String username);
}
