package org.example.authentication.controller;


import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.model.UsersEntity.UserEntity;
import org.example.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody() LoginRequest loginRequest) {
        System.out.println("Login request: " + loginRequest);
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(), loginRequest.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return ResponseEntity.ok("Login successful");
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody() RegisterRequest registerRequest) {
        try {
            System.out.println("Register request: " + registerRequest);
            String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());
            UserEntity user = new UserEntity(
                    registerRequest.getUsername(),
                    encodedPassword,
                    registerRequest.getPhoneNumber(),
                    registerRequest.getEmail(),
                    registerRequest.getFirstName(),
                    registerRequest.getLastName(),
                    "USER"
            );
            userRepository.save(user);
            return ResponseEntity.ok("Register successful");
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/delete/account")
    public ResponseEntity<?> deleteAccount(@RequestBody() String username) {
        try {
            userRepository.delete(userRepository.findByUsername(username));
            return ResponseEntity.ok("Delete successful");
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/test")
    public ResponseEntity<?> test() {
        try {
            UserEntity user = new UserEntity(
                    "admin",
                    passwordEncoder.encode("admin"),
                    "0x0",
                    "abc@12.com",
                    "Hello",
                    "Lo",
                    "ADMIN"
            );
            userRepository.save(user);
//            System.out.println(userRepository.findByUsername("admin").getFullName());
            return ResponseEntity.ok("Register successful");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
}
