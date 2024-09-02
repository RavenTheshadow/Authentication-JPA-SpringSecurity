package org.example.authentication.service;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.springframework.beans.factory.annotation.Value;
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

    private String TokenBuilder(String username) {

        Date currentDate = new Date();

        Date expirationDate = new Date(currentDate.getTime() + jwtExpirationMilliseconds);

        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        Key key = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(currentDate)
                    .setExpiration(expirationDate)
                    .signWith(SignatureAlgorithm.HS256, key).compact();
    }

    @Override
    public Map<String, String> generateToken(String username) {

        Map <String, String> jsonwebToken = new HashMap<>();

        jsonwebToken.put("token", TokenBuilder(username));

        jsonwebToken.put("message", jwtMessage);

        return jsonwebToken;
    }
}
