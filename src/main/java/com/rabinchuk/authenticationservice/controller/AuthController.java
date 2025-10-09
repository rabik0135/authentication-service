package com.rabinchuk.authenticationservice.controller;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequestDto;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponseDto;
import com.rabinchuk.authenticationservice.dto.SignInRequestDto;
import com.rabinchuk.authenticationservice.dto.SignUpRequestDto;
import com.rabinchuk.authenticationservice.dto.TokenRequestDto;
import com.rabinchuk.authenticationservice.dto.UserInfoDto;
import com.rabinchuk.authenticationservice.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    public ResponseEntity<JwtAuthenticationResponseDto> signIn(@Valid @RequestBody SignInRequestDto signInRequestDto) {
        return ResponseEntity.ok(authenticationService.signIn(signInRequestDto));
    }

    @PostMapping("/signUp")
    public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequestDto signUpRequestDto) {
        authenticationService.signUp(signUpRequestDto);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponseDto> refreshToken(@Valid @RequestBody TokenRequestDto tokenRequestDto) {
        return ResponseEntity.ok(authenticationService.refreshToken(tokenRequestDto));
    }

    @PostMapping("/validate")
    public ResponseEntity<UserInfoDto> validateToken(@Valid @RequestBody TokenRequestDto tokenRequestDto) {
        return ResponseEntity.ok(authenticationService.validateToken(tokenRequestDto));
    }

    @PostMapping("/create-admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> createAdmin(@Valid @RequestBody CreateAdminRequestDto createAdminRequestDto) {
        authenticationService.createAdmin(createAdminRequestDto);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

}
