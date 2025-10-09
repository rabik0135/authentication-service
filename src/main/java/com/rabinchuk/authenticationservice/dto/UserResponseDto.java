package com.rabinchuk.authenticationservice.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record UserResponseDto(
        Long id,

        String name,

        String surname,

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
        LocalDate birthDate,

        String email
) {
}
