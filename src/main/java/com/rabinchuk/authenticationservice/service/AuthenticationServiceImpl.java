package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.exception.UserAlreadyExistsException;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import com.rabinchuk.authenticationservice.security.AppUserDetails;
import com.rabinchuk.authenticationservice.security.JwtTokenProvider;

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
        String refreshToken = jwtTokenProvider.generateRefreshToken(appUserDetails);

        return new JwtAuthenticationResponse(accessToken, refreshToken);
    }

    @Override
    public void signUp(SignUpRequest signUpRequest) {
        if (userCredentialsRepository.findByEmail(signUpRequest.email()).isPresent()) {
            throw new UserAlreadyExistsException("Login is already taken");
        }
        UserCredentials userCredentials = UserCredentials.builder()
                .email(signUpRequest.email())
                .password(encoder.encode(signUpRequest.password()))
                .roles(Set.of(RoleType.ROLE_USER))
                .build();
        userCredentialsRepository.save(userCredentials);
    }

    @Override
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        if (!jwtTokenProvider.validateToken(refreshTokenRequest.refreshToken())) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String email = jwtTokenProvider.getEmailFromToken(refreshTokenRequest.refreshToken());
        UserCredentials userCredentials = userCredentialsRepository.findByEmail(email).orElseThrow(
                () -> new UsernameNotFoundException("User not found with email: " + email)
        );

        AppUserDetails appUserDetails = new AppUserDetails(userCredentials);
        String newAccessToken = jwtTokenProvider.generateAccessToken(appUserDetails);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(appUserDetails);

        return new JwtAuthenticationResponse(newAccessToken, newRefreshToken);
    }

    @Override
    public UserInfo validateToken(ValidateTokenRequest validateTokenRequest) {
        if (!jwtTokenProvider.validateToken(validateTokenRequest.token())) {
            throw new BadCredentialsException("Invalid token");
        }

        String login = jwtTokenProvider.getEmailFromToken(validateTokenRequest.token());
        Set<RoleType> roles = jwtTokenProvider.getRolesFromToken(validateTokenRequest.token());

        return new UserInfo(login, roles);
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
