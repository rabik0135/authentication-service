package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

@Builder
public record SignUpAuthRequest(
        String email,
        String password
) {
}
