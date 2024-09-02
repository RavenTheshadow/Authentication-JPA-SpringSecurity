package org.example.authentication.model.Entity.UsersEntity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;


@Setter
@Getter
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String username;
    private String password;
    private String phoneNumber;
    private String email;
    private String fullName;
    private String role;

    protected UserEntity() {}

    public UserEntity(String username, String password, String phoneNumber, String email, String firstName, String lastName, String role) {
        this.username = username;
        this.password = password;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.fullName = firstName + " " + lastName;
        this.role = role;
    }
}
