package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import org.springframework.stereotype.Service;

@Service
public interface AuthenticationService {

    JwtAuthenticationResponse signIn(SignInRequest signInRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

    void signUp(SignUpRequest signUpRequest);

    UserInfo validateToken(ValidateTokenRequest validateTokenRequest);

    void createAdmin(CreateAdminRequest createAdminRequest);

}
