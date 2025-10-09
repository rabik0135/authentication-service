package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

@Builder
public record JwtAuthenticationResponseDto(
        String accessToken,

        String refreshToken
) {
}
