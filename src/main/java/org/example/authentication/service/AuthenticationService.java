package org.example.authentication.service;

import jakarta.servlet.http.HttpServletRequest;
import org.example.authentication.exception.UserAlreadyExistedException;
import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.model.User.Details.CustomUserDetails;
import org.example.authentication.model.User.Entity.UserEntity;
import org.example.authentication.repository.UserRepository;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtGeneratorInterface jwtGenerator;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public ResponseEntity<?> loginRequest(LoginRequest loginRequest) throws BadCredentialsException {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadCredentialsException("Invalid username or password");
        }

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String user_id = userDetails.getUserId();

        Map<String, String> response = jwtGenerator.generateToken(authentication);

        response.put("user_id", user_id);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void CheckingValidUserRegister(String username) throws UserAlreadyExistedException {
        if (userRepository.findByUsername(username) != null) {
            throw new UserAlreadyExistedException("User with username " + username + " already exists.");
        }
    }

    public ResponseEntity<?> register(RegisterRequest registerRequest) throws BadCredentialsException {
        try {
            System.out.println("Register request: " + registerRequest);
            CheckingValidUserRegister(registerRequest.getUsername());
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
            return new ResponseEntity<>("Register Successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("User existed", HttpStatus.BAD_REQUEST);
        }
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

    public ResponseEntity<?> logout(HttpServletRequest request)  {
        String token = request.getHeader("Authorization").substring(7);
        jwtGenerator.disableAccessToken(token);
        return new ResponseEntity<>("Logout successful", HttpStatus.OK);
    }
}
