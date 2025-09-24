package com.rabinchuk.authenticationservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record SignUpRequest(
        @NotBlank(message = "Email must not be empty")
        @Email(message = "Email should be valid")
        @Size(min = 3, max = 100, message = "Email must be between 3 and 50 characters")
        String email,

        @NotBlank(message = "Password must not be empty")
        @Size(min = 8, max = 50, message = "Password must be between 8 and 50 characters")
        String password
) {
}
