package org.example.authentication.repository;

import org.example.authentication.model.Entity.UsersEntity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;


public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByUsername(String username);
    UserEntity findById(UUID id);
}
