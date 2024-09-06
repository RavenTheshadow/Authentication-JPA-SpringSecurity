package org.example.authentication.controller;


import org.example.authentication.exception.HttpResponseCode;
import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.service.AuthenticationService;
import org.hibernate.ObjectNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;


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
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token, @RequestBody() String str_uuid) {
        try {
            UUID uuid = UUID.fromString(str_uuid);
            return authenticationService.logout(uuid, token);
        }
        catch (ObjectNotFoundException | ChangeSetPersister.NotFoundException e) {
            return new ResponseEntity<>("Logout Failed", HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader, @RequestBody() String str_uuid) {
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        } else {
            return new ResponseEntity<>("Invalid Authorization header", HttpStatus.BAD_REQUEST);
        }
        return authenticationService.refreshToken(str_uuid, token);
    }

    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        } else {
            return new ResponseEntity<>("Invalid Authorization header", HttpStatus.BAD_REQUEST);
        }
        return authenticationService.validToken(token);
    }

//    @PostMapping("/delete/account")
//    public ResponseEntity<?> deleteAccount(@RequestBody() String username) {
//        try {
//            return ResponseEntity.ok("Delete successful");
//        } catch (BadCredentialsException ex) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
//        }
//    }

//    @PostMapping("/test")
//    public ResponseEntity<?> test() {
//        return authenticationService.test();
//    }
}
