package org.example.authentication.controller;


import jakarta.servlet.http.HttpServletRequest;
import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody() LoginRequest loginRequest) {
        try {
            System.out.println(loginRequest);
            return authenticationService.loginRequest(loginRequest);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Login failed", HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody() RegisterRequest registerRequest) {
        try {
            return authenticationService.register(registerRequest);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Register Failed", HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        return authenticationService.logout(request);
    }
}
