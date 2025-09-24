package com.rabinchuk.authenticationservice.dto;

public record CreateAdminRequest(
        String email,
        String password
) {
}
