package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {

    Optional<RefreshToken> findByToken(String token);

    RefreshToken createRefreshToken(String email);

    RefreshToken verifyExpiration(RefreshToken token);

}
