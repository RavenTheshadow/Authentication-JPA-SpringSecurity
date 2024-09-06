package org.example.authentication.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UserAlreadyExistedException extends Exception {
    public UserAlreadyExistedException(String message) {
        super(message);
    }
}
