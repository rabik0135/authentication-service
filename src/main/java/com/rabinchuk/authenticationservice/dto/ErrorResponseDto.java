package com.rabinchuk.authenticationservice.dto;

import lombok.Builder;

import java.time.LocalDateTime;
import java.util.Map;

@Builder
public record ErrorResponseDto(
        String path,

        String errorMessage,

        int statusCode,

        LocalDateTime timestamp,

        Map<String, String> errors
) {
}
