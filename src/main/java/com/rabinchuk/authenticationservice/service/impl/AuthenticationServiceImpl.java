package com.rabinchuk.authenticationservice.service.impl;

import com.rabinchuk.authenticationservice.client.UserClient;
import com.rabinchuk.authenticationservice.dto.CreateAdminRequestDto;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponseDto;
import com.rabinchuk.authenticationservice.dto.SignInRequestDto;
import com.rabinchuk.authenticationservice.dto.SignUpRequestDto;
import com.rabinchuk.authenticationservice.dto.SignUpUserRequestDto;
import com.rabinchuk.authenticationservice.dto.TokenRequestDto;
import com.rabinchuk.authenticationservice.dto.UserInfoDto;
import com.rabinchuk.authenticationservice.dto.UserResponseDto;
import com.rabinchuk.authenticationservice.exception.RefreshTokenException;
import com.rabinchuk.authenticationservice.exception.UserAlreadyExistsException;
import com.rabinchuk.authenticationservice.mapper.UserMapper;
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
import org.springframework.transaction.annotation.Transactional;

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
    private final UserMapper userMapper;

    @Override
    @Transactional
    public JwtAuthenticationResponseDto signIn(SignInRequestDto signInRequestDto) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInRequestDto.email(), signInRequestDto.password())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Invalid email or password");
        }

        UserCredentials userCredentials = userCredentialsRepository.findByEmail(signInRequestDto.email())
                .orElseThrow(
                        () -> new UsernameNotFoundException("User not found with email: " + signInRequestDto.email())
                );

        AppUserDetails appUserDetails = new AppUserDetails(userCredentials);
        String accessToken = jwtTokenProvider.generateAccessToken(appUserDetails);
        RefreshToken refreshToken = refreshTokenServiceImpl.createRefreshToken(signInRequestDto.email());

        return new JwtAuthenticationResponseDto(accessToken, refreshToken.getToken());
    }

    @Override
    @Transactional
    public void signUp(SignUpRequestDto signUpRequestDto) {
        if (userCredentialsRepository.existsByEmail(signUpRequestDto.email())) {
            throw new UserAlreadyExistsException("Login is already taken");
        }

        SignUpUserRequestDto signUpUserRequestDto = userMapper.toSignUpUserRequest(signUpRequestDto);
        UserResponseDto userResponseDto = userClient.createUser(signUpUserRequestDto);

        if (userResponseDto == null) {
            throw new RuntimeException("Failed to create user in User service");
        }

        UserCredentials userCredentials = userMapper.toUserCredentials(signUpRequestDto);
        userCredentials.setPassword(encoder.encode(signUpRequestDto.password()));

        try {
            userCredentialsRepository.save(userCredentials);
        } catch (Exception ex) {
            userClient.deleteUser(userResponseDto.id());
            throw new RuntimeException("Couldn't save credentials. Rolling back.", ex);
        }
    }

    @Override
    public JwtAuthenticationResponseDto refreshToken(TokenRequestDto tokenRequestDto) {
        return refreshTokenServiceImpl.findByToken(tokenRequestDto.token())
                .map(refreshTokenServiceImpl::verifyExpiration)
                .map(RefreshToken::getUserCredentials)
                .map(userCredentials -> {
                    AppUserDetails appUserDetails = new AppUserDetails(userCredentials);
                    String newAccessToken = jwtTokenProvider.generateAccessToken(appUserDetails);

                    return new JwtAuthenticationResponseDto(newAccessToken, tokenRequestDto.token());
                })
                .orElseThrow(
                        () -> new RefreshTokenException(tokenRequestDto.token(), "Refresh token is not in database or expired")
                );
    }

    @Override
    public UserInfoDto validateToken(TokenRequestDto tokenRequestDto) {
        if (!jwtTokenProvider.validateToken(tokenRequestDto.token())) {
            throw new BadCredentialsException("Invalid token");
        }

        String email = jwtTokenProvider.getEmailFromToken(tokenRequestDto.token());
        Set<RoleType> roles = jwtTokenProvider.getRolesFromToken(tokenRequestDto.token());

        return new UserInfoDto(email, roles);
    }

    @Override
    public void createAdmin(CreateAdminRequestDto createAdminRequestDto) {
        if (userCredentialsRepository.findByEmail(createAdminRequestDto.email()).isPresent()) {
            throw new UserAlreadyExistsException("Email is already taken");
        }

        UserCredentials adminCredentials = UserCredentials.builder()
                .email(createAdminRequestDto.email())
                .password(encoder.encode(createAdminRequestDto.password()))
                .roles(Set.of(RoleType.ROLE_ADMIN))
                .build();

        userCredentialsRepository.save(adminCredentials);
    }

}
