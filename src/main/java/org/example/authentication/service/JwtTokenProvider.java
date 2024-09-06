package org.example.authentication.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.example.authentication.model.JWT.JWTToken;
import org.example.authentication.repository.JwtRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider implements JwtGeneratorInterface {
    @Value("${app.jwt-message}")
    private String jwtMessage;

    @Value("${app.jwt-expiration}")
    private long jwtExpirationMilliseconds;

    @Value("${app.jwt-secret-key}")
    private String jwtSecretKey;

    private final JwtRepository jwtRepository;
    private final Key key;

    public JwtTokenProvider(JwtRepository jwtRepository,
                            @Value("${app.jwt-secret-key}") String jwtSecretKey) {
        this.jwtRepository = jwtRepository;
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        this.key = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    private String createToken(String username) {
        Date currentDate = new Date();
        Date expirationDate = new Date(currentDate.getTime() + jwtExpirationMilliseconds);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(currentDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256 ,key)
                .compact();
    }

    @Override
    public Map<String, String> generateToken(String username) {
        String token = createToken(username);
        jwtRepository.save(new JWTToken(token, new Date(), new Date(System.currentTimeMillis() + jwtExpirationMilliseconds), true));

        Map<String, String> response = new HashMap<>();
        response.put("message", jwtMessage);
        response.put("token", token);

        return response;
    }

    @Override
    public boolean validateToken(String token) throws ChangeSetPersister.NotFoundException {
        JWTToken jwtToken = jwtRepository.findByToken(token);
        if (jwtToken == null || !jwtToken.isActive() || jwtToken.getExpiresAt().before(new Date())) {
            throw new ChangeSetPersister.NotFoundException();
        }
        return true;
    }

    @Override
    public void disableAccessToken(String token) throws ChangeSetPersister.NotFoundException {
        JWTToken jwtToken = jwtRepository.findByToken(token);
        if (jwtToken == null) {
            throw new ChangeSetPersister.NotFoundException();
        }
        jwtToken.setActive(false);
        jwtRepository.save(jwtToken);
    }

    @Override
    public Map<String, String> refreshToken(String username) {
        return generateToken(username);
    }
}
