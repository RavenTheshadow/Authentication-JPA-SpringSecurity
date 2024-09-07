package org.example.authentication.service;

import org.example.authentication.exception.UserAlreadyExistedException;
import org.example.authentication.model.Form.LoginRequest;
import org.example.authentication.model.Form.RegisterRequest;
import org.example.authentication.model.User.Details.CustomUserDetails;
import org.example.authentication.model.User.Entity.UserEntity;
import org.example.authentication.repository.UserRepository;
import org.example.authentication.config.jwt.JwtGeneratorInterface;
import org.hibernate.ObjectNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
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

import java.util.Map;
import java.util.UUID;

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

//    public ResponseEntity<?> logout(UUID uuid, String token) throws ObjectNotFoundException, ChangeSetPersister.NotFoundException {
//        UserEntity user = userRepository.findById(uuid);
//
//        SecurityContextHolder.getContext().setAuthentication(null);
//
//        try {
//            if (jwtGenerator.validateToken(token)) {
//                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
//            }
//            jwtGenerator.disableAccessToken(token);
//        } catch (ChangeSetPersister.NotFoundException e) {
//            throw new ChangeSetPersister.NotFoundException();
//        }
//
//        return new ResponseEntity<>("Logout successful", HttpStatus.OK);
//    }
//
//    public ResponseEntity<?> refreshToken(String str_uuid, String token) {
//        try {
//            UserEntity user = userRepository.findById(UUID.fromString(str_uuid));
//            String username = user.getUsername();
//
//            if (!jwtGenerator.validateToken(token)) {
//                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
//            }
//
//            jwtGenerator.disableAccessToken(token);
//
//            Map<String, String> response = jwtGenerator.refreshToken(username);
//            return new ResponseEntity<>(response, HttpStatus.OK);
//
//        } catch (ChangeSetPersister.NotFoundException e) {
//            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
//        }
//    }
//
//    public ResponseEntity<?> validToken(String token) {
//        try {
//            if (jwtGenerator.validateToken(token)) {
//                return new ResponseEntity<>("Token is valid", HttpStatus.OK);
//            } else {
//                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
//            }
//        } catch (Exception e) {
//            return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
//        }
//    }
}
