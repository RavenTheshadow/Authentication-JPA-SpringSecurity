package org.example.authentication.repository;

import org.example.authentication.model.Entity.UsersEntity.JWTToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JwtRepository extends JpaRepository<JWTToken, String> {
    public JWTToken findByToken(String token);
}
