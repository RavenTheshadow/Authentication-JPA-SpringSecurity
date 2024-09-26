package org.example.authentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider implements JwtGeneratorInterface {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final String AUTHORITIES_KEY = "auth";

    @Value("${app.jwt-expiration}")
    private long tokenValidityInMilliSeconds;

    @Value("${app.jwt-secret-key}")
    private String secretKey;

    private String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + tokenValidityInMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .compact();
    }
    @Override
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    @Override
    public Map<String, String> generateToken(Authentication authentication) {
        String jwt_token = createToken(authentication);
        Map<String, String> response = new HashMap<>();
        response.put("token", jwt_token);
        response.put("message", "Create jwt token successfully");
        return response;
    }

    @Override
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("Invalid JWT signature: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            LOGGER.error("JWT token validation error: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public void disableAccessToken(String token) {

    }
}
