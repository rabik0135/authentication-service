package com.rabinchuk.authenticationservice.service.impl;

import com.rabinchuk.authenticationservice.exception.RefreshTokenException;
import com.rabinchuk.authenticationservice.model.RefreshToken;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.RefreshTokenRepository;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import com.rabinchuk.authenticationservice.security.AppUserDetails;
import com.rabinchuk.authenticationservice.security.JwtTokenProvider;
import com.rabinchuk.authenticationservice.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Value("${app.jwt.refreshTokenExpiration}")
    private long refreshTokenExpiration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public RefreshToken createRefreshToken(String email) {
        UserCredentials userCredentials = userCredentialsRepository.findByEmail(email).orElseThrow(
                () -> new UsernameNotFoundException("User not found with email: " + email)
        );

        refreshTokenRepository.deleteByUserCredentials(userCredentials);

        AppUserDetails appUserDetails = new AppUserDetails(userCredentials);

        String token = jwtTokenProvider.generateRefreshToken(appUserDetails);

        RefreshToken refreshToken = RefreshToken.builder()
                .userCredentials(userCredentials)
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration))
                .token(token)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RefreshTokenException(token.getToken(), "Refresh token expired");
        }
        return token;
    }

}
