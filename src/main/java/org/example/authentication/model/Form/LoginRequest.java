package org.example.authentication.model.Form;


import lombok.*;


@Setter
@Getter
@Data
public class LoginRequest {
    private String username;
    private String password;

    public LoginRequest() {}
    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

}
