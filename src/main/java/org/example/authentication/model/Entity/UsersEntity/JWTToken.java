package org.example.authentication.model.Entity.UsersEntity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Table(name = "JwtToken")
@Getter
@Setter
public class JWTToken {
    @Id
    @GeneratedValue()
    private Long id;
    private String token;
    private boolean isActive;
    private Date createAt;
    private Date expiresAt;

    protected JWTToken() {}

    public JWTToken(String token, Date createAt, Date expiresAt, boolean isActive) {
        this.token = token;
        this.createAt = createAt;
        this.expiresAt = expiresAt;
        this.isActive = isActive;
    }
}
