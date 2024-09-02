package org.example.authentication.service;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.example.authentication.model.Entity.UsersEntity.JWTToken;
import org.example.authentication.repository.JwtRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Component;


import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.text.SimpleDateFormat;
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

    @Autowired
    private JwtRepository jwtRepository;

    Date currentDate;
    Date expirationDate;

    private String TokenBuilder(String username) {

        currentDate = new Date();

        expirationDate = new Date(currentDate.getTime() + jwtExpirationMilliseconds);

        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        Key key = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());

        String jwt_token =  Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(currentDate)
                    .setExpiration(expirationDate)
                    .signWith(SignatureAlgorithm.HS256, key).compact();

        jwtRepository.save(new JWTToken(jwt_token, currentDate, expirationDate, true));

        return jwt_token;
    }

    private String RefreshTokenBuilder(String username) {
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        Key key = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
        Date refreshExpirationDate = new Date(expirationDate.getTime() + jwtExpirationMilliseconds + 600);
        String jwt_refresh_token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(currentDate)
                .setExpiration(refreshExpirationDate)
                .signWith(SignatureAlgorithm.HS512, key).compact();

        jwtRepository.save(new JWTToken(jwt_refresh_token, currentDate, refreshExpirationDate, true));
        return jwt_refresh_token;
    }



    @Override
    public Map<String, String> generateToken(String username) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        Map <String, String> jsonwebToken = new HashMap<>();

        jsonwebToken.put("message", jwtMessage);

        jsonwebToken.put("token", TokenBuilder(username));

        jsonwebToken.put("refresh_token", RefreshTokenBuilder(username));

        jsonwebToken.put("created_at", dateFormat.format(currentDate.getTime()));

        jsonwebToken.put("expiration", dateFormat.format(expirationDate.getTime()));

        return jsonwebToken;
    }

    @Override
    public boolean validateToken(String token) throws ChangeSetPersister.NotFoundException {

        JWTToken my_token = jwtRepository.findByToken(token);
        currentDate = new Date();
        return !my_token.getExpiresAt().before(currentDate);
    }

    @Override
    public boolean freeToken(String token) throws ChangeSetPersister.NotFoundException {
        JWTToken my_token = jwtRepository.findByToken(token);
        jwtRepository.delete(my_token);

        return true;
    }

    @Override
    public void disableAccessToken(String token) throws ChangeSetPersister.NotFoundException {
        JWTToken my_token = jwtRepository.findByToken(token);
        my_token.setActive(false);
        jwtRepository.save(my_token);
    }
}
