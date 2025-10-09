package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequestDto;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponseDto;
import com.rabinchuk.authenticationservice.dto.SignInRequestDto;
import com.rabinchuk.authenticationservice.dto.SignUpRequestDto;
import com.rabinchuk.authenticationservice.dto.TokenRequestDto;
import com.rabinchuk.authenticationservice.dto.UserInfoDto;
import org.springframework.stereotype.Service;

@Service
public interface AuthenticationService {

    JwtAuthenticationResponseDto signIn(SignInRequestDto signInRequestDto);

    JwtAuthenticationResponseDto refreshToken(TokenRequestDto tokenRequestDto);

    void signUp(SignUpRequestDto signUpRequestDto);

    UserInfoDto validateToken(TokenRequestDto tokenRequestDto);

    void createAdmin(CreateAdminRequestDto createAdminRequestDto);

}
