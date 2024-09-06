package org.example.authentication.repository;

import org.example.authentication.model.JWT.JWTToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JwtRepository extends JpaRepository<JWTToken, String> {
    public JWTToken findByToken(String token);
}
