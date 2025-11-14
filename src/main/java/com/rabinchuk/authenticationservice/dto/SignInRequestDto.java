package com.rabinchuk.authenticationservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record SignInRequestDto(
        @NotBlank(message = "Email must not be empty")
        @Email(message = "Email should be valid")
        String email,

        @NotBlank(message = "Password must not be empty")
        String password
) {
}
