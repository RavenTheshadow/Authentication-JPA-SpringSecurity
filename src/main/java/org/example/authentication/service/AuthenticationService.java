package org.example.authentication.service;

import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.model.UsersEntity.UserEntity;
import org.example.authentication.repository.UserRepository;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.hibernate.ObjectNotFoundException;
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
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtGeneratorInterface jwtGenerator;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public ResponseEntity<?> loginRequest(LoginRequest loginRequest) throws BadCredentialsException {
        System.out.println("Login request: " + loginRequest);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(), loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return new ResponseEntity<>(jwtGenerator.generateToken(loginRequest.getUsername()), HttpStatus.OK);
    }

    public ResponseEntity<?> register(RegisterRequest registerRequest) throws BadCredentialsException {
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
    }

    public ResponseEntity<?> test() throws BadCredentialsException {
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
            return ResponseEntity.ok("Register successful");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    public ResponseEntity<?> logout(UUID uuid) throws ObjectNotFoundException {
        UserEntity user = userRepository.findById(uuid);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        userRepository.delete(user);
        return ResponseEntity.ok("Logout successful");
    }
}
