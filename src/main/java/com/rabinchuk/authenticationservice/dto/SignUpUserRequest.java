package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

import java.time.LocalDate;

@Builder
public record SignUpUserRequest(
        String name,

        String surname,

        LocalDate birthDate,

        String email
) {
}
