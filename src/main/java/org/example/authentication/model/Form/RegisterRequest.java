package org.example.authentication.model.Form;

import lombok.Data;

@Data
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String confirmPassword;
    private String email;
    private String phoneNumber;

    public RegisterRequest() {}

    public RegisterRequest(String firstName, String lastName, String username, String password, String confirmPassword, String email, String phoneNumber) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.username = username;
        this.password = password;
        this.confirmPassword = confirmPassword;
        this.email = email;
        this.phoneNumber = phoneNumber;
    }
}
