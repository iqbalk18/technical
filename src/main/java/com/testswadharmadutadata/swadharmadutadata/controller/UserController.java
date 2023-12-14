package com.testswadharmadutadata.swadharmadutadata.controller;

import com.testswadharmadutadata.swadharmadutadata.exception.*;
import com.testswadharmadutadata.swadharmadutadata.model.ErrorResponse;
import com.testswadharmadutadata.swadharmadutadata.model.forgotmodel.ChangePasswordRequest;
import com.testswadharmadutadata.swadharmadutadata.model.forgotmodel.ChangePasswordResponse;
import com.testswadharmadutadata.swadharmadutadata.model.forgotmodel.ForgotPasswordRequest;
import com.testswadharmadutadata.swadharmadutadata.model.forgotmodel.ForgotPasswordResponse;
import com.testswadharmadutadata.swadharmadutadata.model.loginmodel.AuthenticationRequest;
import com.testswadharmadutadata.swadharmadutadata.model.loginmodel.AuthenticationResponse;
import com.testswadharmadutadata.swadharmadutadata.model.registermodel.RegisterRequest;
import com.testswadharmadutadata.swadharmadutadata.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin
public class UserController {
    private final AuthenticationService service;

    @PostMapping("/register/mail")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = service.register(request);
            return ResponseEntity.ok(response);
        } catch (EmailAlreadyExistsException ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse("error", "Email already registered"));
        }
    }

    @GetMapping(path = "confirm")
    public ResponseEntity<String> confirm(@RequestParam("token") String token) {
        try {
            service.confirmToken(token);
            return ResponseEntity.ok("User registration confirmed successfully.");
        } catch (TokenExpiredException e) {
            return ResponseEntity.badRequest().body("Token has expired. Please register again.");
        } catch (TokenNotFoundException e) {
            return ResponseEntity.badRequest().body("Invalid token. Please check your email for the correct link.");
        } catch (CustomException e) {
            return ResponseEntity.badRequest().body("Some other error occurred.");
        }
    }


    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        try {
            AuthenticationResponse response = service.authenticate(request);
            return ResponseEntity.ok(response);
        } catch (EmailNotConfirmedException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED) .body(new ErrorResponse("error","Account not found, please registration with email"));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("error","Invalid Email and Password"));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ForgotPasswordResponse> requestPasswordReset(@RequestBody ForgotPasswordRequest request) {
        ForgotPasswordResponse response = service.requestPasswordReset(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-change-password")
    public ResponseEntity<ChangePasswordResponse> changePassword(@RequestBody ChangePasswordRequest request) {
        ChangePasswordResponse response = service.forgotChangePassword(request);
        return ResponseEntity.ok(response);
    }
}
