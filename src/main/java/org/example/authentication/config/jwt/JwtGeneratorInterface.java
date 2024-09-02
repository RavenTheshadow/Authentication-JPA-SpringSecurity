package org.example.authentication.config.jwt;

import org.springframework.data.crossstore.ChangeSetPersister;

import java.util.Map;

public interface JwtGeneratorInterface {
    Map<String, String> generateToken(String username);

    boolean validateToken(String refresh_token) throws ChangeSetPersister.NotFoundException;
    boolean freeToken(String token) throws ChangeSetPersister.NotFoundException;
    void disableAccessToken(String token) throws ChangeSetPersister.NotFoundException;
}
