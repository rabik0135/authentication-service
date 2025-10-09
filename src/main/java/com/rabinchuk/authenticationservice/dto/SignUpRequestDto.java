package com.rabinchuk.authenticationservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record SignUpRequestDto(
        @NotBlank(message = "Email must not be empty")
        @Email(message = "Email should be valid")
        @Size(min = 3, max = 100, message = "Email must be between 3 and 50 characters")
        String email,

        @NotBlank(message = "Password must not be empty")
        @Size(min = 8, max = 50, message = "Password must be between 8 and 50 characters")
        String password,

        @NotBlank(message = "Name is required")
        @Size(max = 50, message = "Name must not exceed 50 characters")
        String name,

        @NotBlank(message = "Surname is required")
        @Size(max = 50, message = "Surname must not exceed 50 characters")
        String surname,

        @NotNull(message = "Birth date is required")
        @Past(message = "Birth date must be in the past")
        LocalDate birthDate
) {
}
