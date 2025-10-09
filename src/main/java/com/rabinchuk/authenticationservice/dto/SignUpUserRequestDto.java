package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

import java.time.LocalDate;

@Builder
public record SignUpUserRequestDto(
        String name,

        String surname,

        LocalDate birthDate,

        String email
) {
}
