package com.rabinchuk.authenticationservice.controller;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signIn")
    public ResponseEntity<JwtAuthenticationResponse> signIn(@Valid @RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authenticationService.signIn(signInRequest));
    }

    @PostMapping("/signUp")
    public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest signUpRequest) {
        authenticationService.signUp(signUpRequest);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/validate")
    public ResponseEntity<UserInfo> validateToken(@Valid @RequestBody ValidateTokenRequest validateTokenRequest) {
        return ResponseEntity.ok(authenticationService.validateToken(validateTokenRequest));
    }

    @PostMapping("/create-admin")
    public ResponseEntity<Void> createAdmin(@Valid @RequestBody CreateAdminRequest createAdminRequest) {
        authenticationService.createAdmin(createAdminRequest);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

}
