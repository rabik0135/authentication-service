package com.rabinchuk.authenticationservice.service.impl;

import com.rabinchuk.authenticationservice.client.UserClient;
import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpAuthRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.SignUpUserRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.UserResponse;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.exception.RefreshTokenException;
import com.rabinchuk.authenticationservice.exception.UserAlreadyExistsException;
import com.rabinchuk.authenticationservice.model.RefreshToken;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import com.rabinchuk.authenticationservice.security.AppUserDetails;
import com.rabinchuk.authenticationservice.security.JwtTokenProvider;
import com.rabinchuk.authenticationservice.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenServiceImpl refreshTokenServiceImpl;
    private final UserClient userClient;

    @Override
    public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInRequest.email(), signInRequest.password())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Invalid email or password");
        }

        UserCredentials userCredentials = userCredentialsRepository.findByEmail(signInRequest.email())
                .orElseThrow(
                        () -> new UsernameNotFoundException("User not found with email: " + signInRequest.email())
                );

        AppUserDetails appUserDetails = new AppUserDetails(userCredentials);
        String accessToken = jwtTokenProvider.generateAccessToken(appUserDetails);
        RefreshToken refreshToken = refreshTokenServiceImpl.createRefreshToken(signInRequest.email());

        return new JwtAuthenticationResponse(accessToken, refreshToken.getToken());
    }

    @Override
    public void signUp(SignUpRequest signUpRequest) {
        SignUpUserRequest signUpUserRequest = SignUpUserRequest.builder()
                .name(signUpRequest.name())
                .surname(signUpRequest.surname())
                .birthDate(signUpRequest.birthDate())
                .email(signUpRequest.email())
                .build();
        SignUpAuthRequest signUpAuthRequest = SignUpAuthRequest.builder()
                .email(signUpRequest.email())
                .password(signUpRequest.password())
                .build();

        if (userCredentialsRepository.findByEmail(signUpRequest.email()).isPresent()) {
            throw new UserAlreadyExistsException("Login is already taken");
        }

        UserResponse userResponse = userClient.createUser(signUpUserRequest);

        if (userResponse == null) {
            throw new RuntimeException("Failed to create user in User service");
        }

        UserCredentials userCredentials = UserCredentials.builder()
                .email(signUpRequest.email())
                .password(encoder.encode(signUpRequest.password()))
                .roles(Set.of(RoleType.ROLE_USER))
                .build();
        try {
            userCredentialsRepository.save(userCredentials);
        } catch (Exception ex) {
            userClient.deleteUser(userResponse.id());
            throw new RuntimeException("Couldn't save credentials. Rolling back.", ex);
        }
    }

    @Override
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        return refreshTokenServiceImpl.findByToken(refreshTokenRequest.refreshToken())
                .map(refreshTokenServiceImpl::verifyExpiration)
                .map(RefreshToken::getUserCredentials)
                .map(userCredentials -> {
                    AppUserDetails appUserDetails = new AppUserDetails(userCredentials);
                    String newAccessToken = jwtTokenProvider.generateAccessToken(appUserDetails);

                    return new JwtAuthenticationResponse(newAccessToken, refreshTokenRequest.refreshToken());
                })
                .orElseThrow(
                        () -> new RefreshTokenException(refreshTokenRequest.refreshToken(), "Refresh token is not in database or expired")
                );
    }

    @Override
    public UserInfo validateToken(ValidateTokenRequest validateTokenRequest) {
        if (!jwtTokenProvider.validateToken(validateTokenRequest.token())) {
            throw new BadCredentialsException("Invalid token");
        }

        String email = jwtTokenProvider.getEmailFromToken(validateTokenRequest.token());
        Set<RoleType> roles = jwtTokenProvider.getRolesFromToken(validateTokenRequest.token());

        return new UserInfo(email, roles);
    }

    @Override
    public void createAdmin(CreateAdminRequest createAdminRequest) {
        if (userCredentialsRepository.findByEmail(createAdminRequest.email()).isPresent()) {
            throw new UserAlreadyExistsException("Email is already taken");
        }

        UserCredentials adminCredentials = UserCredentials.builder()
                .email(createAdminRequest.email())
                .password(encoder.encode(createAdminRequest.password()))
                .roles(Set.of(RoleType.ROLE_ADMIN))
                .build();

        userCredentialsRepository.save(adminCredentials);
    }

}
