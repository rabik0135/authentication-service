package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

@Builder
public record JwtAuthenticationResponse(
        String accessToken,
        String refreshToken
) {
}
