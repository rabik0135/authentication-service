package com.rabinchuk.authenticationservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record ValidateTokenRequest(
        @NotBlank
        String token
) {
}
